use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::rc::Rc;

use sha2::{Digest, Sha256};

use crate::arm::{BeginEndBlock, Instr};
use crate::sexp::{CreateSExp, Number, SExp, SExpValue, Srcloc, bi_one, bi_zero};

use gimli;
use gimli::Arm;
use gimli::constants::{
    DW_AT_byte_size, DW_AT_encoding, DW_AT_frame_base, DW_AT_high_pc, DW_AT_language,
    DW_AT_location, DW_AT_low_pc, DW_AT_name, DW_AT_type, DW_LANG_C99, DW_TAG_base_type,
    DW_TAG_formal_parameter, DW_TAG_pointer_type, DW_TAG_subprogram,
};
use gimli::write::{
    Address, AttributeValue, CallFrameInstruction, CieId, CommonInformationEntry, DirectoryId,
    Dwarf, Expression, FileId, FrameDescriptionEntry, FrameTable, LineProgram, LineString,
    Location, LocationList, Range, RangeList, Section, Sections, Unit, UnitEntryId, UnitId,
};
use gimli::{DW_ATE_unsigned, Encoding, Format, LineEncoding};

#[derive(Clone)]
struct DwarfLineRow {
    filename: String,
    line: u64,
    col: u64,
}

pub struct DwarfBuilder {
    unit_id: UnitId,
    file_to_id: HashMap<Vec<u8>, (DirectoryId, FileId)>,
    directory_to_id: HashMap<Vec<u8>, DirectoryId>,
    synthetic_source_path: String,
    synthetic_file_id: Option<FileId>,
    synthetic_source_lines: Vec<String>,
    synthetic_expr_line_by_key: HashMap<Vec<u8>, u64>,
    pointer_type: UnitEntryId,
    u32_type: UnitEntryId,

    seq_addr_start: usize,
    target_addr: u32,

    symbol_table: Rc<HashMap<String, String>>,

    dwarf: Dwarf,
    frame_table: FrameTable,
    cfi_cie_id: Option<CieId>,
    last_row_source: Option<DwarfLineRow>,
    last_statement_source_line: Option<(String, u64)>,
}

struct VariableLocationInfo<'a> {
    pub beginning: u64,
    pub end: u64,
    start_expr: &'a dyn Fn() -> Expression,
}

#[derive(Default, Clone, Debug)]
struct DwarfSectionWriter {
    pub written: Vec<u8>,
}

impl gimli::write::Writer for DwarfSectionWriter {
    type Endian = gimli::LittleEndian;

    fn endian(&self) -> Self::Endian {
        gimli::LittleEndian
    }

    fn len(&self) -> usize {
        self.written.len()
    }

    fn write(&mut self, bytes: &[u8]) -> gimli::write::Result<()> {
        for b in bytes.iter() {
            self.written.push(*b);
        }

        Ok(())
    }

    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> gimli::write::Result<()> {
        let mut to_skip = 0;
        if offset < self.written.len() {
            to_skip = self.written.len() - offset;
            for (i, b) in bytes.iter().enumerate().take(to_skip) {
                self.written[offset + i] = *b;
            }
        }

        while offset > self.written.len() {
            self.written.push(0);
        }

        for b in bytes.iter().skip(to_skip) {
            self.written.push(*b);
        }

        Ok(())
    }
}

impl DwarfBuilder {
    pub fn new(
        filename: &str,
        elf_output: &str,
        target_addr: u32,
        symbol_table: Rc<HashMap<String, String>>,
    ) -> Self {
        let mut path = PathBuf::new();
        path.push(filename);
        path.pop();
        let mut dirname = path.into_os_string().to_string_lossy().as_bytes().to_vec();

        if dirname.is_empty() {
            dirname = b".".to_vec();
        }

        path = PathBuf::new();
        path.push(filename);
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().as_bytes().to_vec())
            .unwrap_or_else(|| filename.as_bytes().to_vec());

        let line_encoding = LineEncoding {
            minimum_instruction_length: 4,
            maximum_operations_per_instruction: 1,
            default_is_stmt: false,
            line_base: 0,
            line_range: 1,
        };

        let mut dwarf = Dwarf::default();
        let encoding = Encoding {
            address_size: 4,
            format: Format::Dwarf32,
            version: 2,
        };

        let dirstring = LineString::String(dirname.clone());
        let filestring = LineString::String(filename.clone());
        let mut line_program = LineProgram::new(
            encoding,
            line_encoding,
            dirstring.clone(),
            filestring.clone(),
            None,
        );
        let mut directory_to_id = HashMap::new();
        let directory_id = line_program.add_directory(dirstring);
        directory_to_id.insert(dirname.clone(), directory_id);
        let mut file_to_id = HashMap::new();
        let file_id = line_program.add_file(filestring, directory_id, None);
        file_to_id.insert(filename.clone(), (directory_id, file_id));

        let mut unit = Unit::new(encoding, line_program);

        unit.ranges.add(RangeList(vec![Range::BaseAddress {
            address: Address::Constant(target_addr as u64),
        }]));
        unit.locations.add(LocationList(vec![Location::BaseAddress {
            address: Address::Constant(target_addr as u64),
        }]));
        let unit_ent = unit.get_mut(unit.root());
        unit_ent.set(
            DW_AT_low_pc,
            AttributeValue::Address(Address::Constant((target_addr) as u64)),
        );
        unit_ent.set(DW_AT_name, AttributeValue::String(filename.clone()));
        unit_ent.set(DW_AT_language, AttributeValue::Language(DW_LANG_C99));

        let unit_id = dwarf.units.add(unit);
        let mutable_unit = dwarf.units.get_mut(unit_id);
        let base_type_id = mutable_unit.add(mutable_unit.root(), DW_TAG_base_type);
        let base_ent = mutable_unit.get_mut(base_type_id);
        base_ent.set(DW_AT_byte_size, AttributeValue::Data1(4));
        base_ent.set(DW_AT_encoding, AttributeValue::Encoding(DW_ATE_unsigned));
        base_ent.set(DW_AT_name, AttributeValue::String(b"word".to_vec()));
        let type_id = mutable_unit.add(mutable_unit.root(), DW_TAG_pointer_type);
        let type_ent = mutable_unit.get_mut(type_id);
        type_ent.set(DW_AT_name, AttributeValue::String(b"sexp".to_vec()));
        type_ent.set(DW_AT_byte_size, AttributeValue::Udata(4));
        type_ent.set(DW_AT_type, AttributeValue::UnitRef(base_type_id));

        let mut obj = DwarfBuilder {
            seq_addr_start: 0,
            target_addr,
            unit_id,
            file_to_id,
            directory_to_id,
            synthetic_source_path: format!("{elf_output}.clsp"),
            synthetic_file_id: None,
            synthetic_source_lines: Vec::new(),
            synthetic_expr_line_by_key: HashMap::new(),
            pointer_type: type_id,
            u32_type: base_type_id,
            symbol_table,
            dwarf,
            frame_table: FrameTable::default(),
            cfi_cie_id: None,
            last_row_source: None,
            last_statement_source_line: None,
        };
        let cfi_encoding = Encoding {
            address_size: 4,
            format: Format::Dwarf32,
            version: 1,
        };
        let mut cie = CommonInformationEntry::new(cfi_encoding, 1, -4, Arm::R14);
        cie.add_instruction(CallFrameInstruction::Cfa(Arm::R13, 0));
        obj.cfi_cie_id = Some(obj.frame_table.add_cie(cie));

        let synthetic_source_path = obj.synthetic_source_path.clone();
        let (_, synthetic_file_id) = obj.add_file(&synthetic_source_path);
        obj.synthetic_file_id = Some(synthetic_file_id);

        obj
    }

    fn add_file_having_dirid(
        &mut self,
        dirid: DirectoryId,
        filename: &[u8],
    ) -> (DirectoryId, FileId) {
        let unit = self.dwarf.units.get_mut(self.unit_id);
        let filestring = LineString::String(filename.to_vec());
        let fileid = unit.line_program.add_file(filestring, dirid, None);
        self.file_to_id.insert(filename.to_vec(), (dirid, fileid));
        (dirid, fileid)
    }

    fn add_file(&mut self, filename_str: &str) -> (DirectoryId, FileId) {
        let mut path = PathBuf::new();
        path.push(filename_str);
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().as_bytes().to_vec())
            .unwrap_or_else(|| filename_str.as_bytes().to_vec());
        if let Some((dirid, fileid)) = self.file_to_id.get(&filename) {
            return (*dirid, *fileid);
        }

        path = PathBuf::new();
        path.push(filename_str);
        path.pop();

        let dirname = path.into_os_string().to_string_lossy().as_bytes().to_vec();
        let use_dirname = if dirname.is_empty() {
            vec![b'.']
        } else {
            dirname.clone()
        };

        if let Some(dirid) = self.directory_to_id.get(&use_dirname) {
            return self.add_file_having_dirid(*dirid, &filename);
        }

        let dirstring = LineString::String(use_dirname.clone());
        let unit = self.dwarf.units.get_mut(self.unit_id);
        let dirid = unit.line_program.add_directory(dirstring);
        self.directory_to_id.insert(use_dirname, dirid);
        self.add_file_having_dirid(dirid, &filename)
    }

    fn synthetic_expr_key<C: CreateSExp>(loc: &C::SL, source_sexp: &impl fmt::Display) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(loc.filename().as_bytes());
        hasher.update((loc.line() as u64).to_le_bytes());
        hasher.update((loc.col() as u64).to_le_bytes());
        if let Some(until) = loc.until() {
            hasher.update((until.line as u64).to_le_bytes());
            hasher.update((until.col as u64).to_le_bytes());
        }
        hasher.update(source_sexp.to_string().as_bytes());
        hasher.finalize().to_vec()
    }

    fn add_synthetic_line<C: CreateSExp>(
        &mut self,
        loc: &C::SL,
        source_sexp: &impl fmt::Display,
    ) -> u64 {
        let synthetic_key = Self::synthetic_expr_key::<C>(loc, source_sexp);
        if let Some(line) = self.synthetic_expr_line_by_key.get(&synthetic_key) {
            return *line;
        }

        const MAX_SYNTHETIC_EXPR_CHARS: usize = 220;
        let expression = source_sexp.to_string();
        let truncated: String = expression.chars().take(MAX_SYNTHETIC_EXPR_CHARS).collect();
        let display_expr = if expression.chars().count() > MAX_SYNTHETIC_EXPR_CHARS {
            format!("{truncated}...")
        } else {
            truncated
        };
        self.synthetic_source_lines
            .push(format!("{loc} => {display_expr}"));
        let line = self.synthetic_source_lines.len() as u64;
        self.synthetic_expr_line_by_key.insert(synthetic_key, line);
        line
    }

    pub fn synthetic_source(&self) -> String {
        let mut synthetic_source = self.synthetic_source_lines.join("\n");
        if !synthetic_source.is_empty() {
            synthetic_source.push('\n');
        }
        synthetic_source
    }

    pub fn add_instr<C: CreateSExp>(
        &mut self,
        addr: usize,
        loc: &C::SL,
        source_sexp: &impl fmt::Display,
        instr: Instr,
        begin_end_block: Option<BeginEndBlock>,
    ) {
        if !self
            .dwarf
            .units
            .get_mut(self.unit_id)
            .line_program
            .in_sequence()
        {
            return;
        }

        let source_file = loc.filename();
        let synthetic_file_id = self
            .synthetic_file_id
            .expect("synthetic source file registered");
        let using_synthetic_file = loc.filename().starts_with('*');
        let (file_id, line, col) = if using_synthetic_file {
            (
                synthetic_file_id,
                self.add_synthetic_line::<C>(loc, source_sexp),
                1_u64,
            )
        } else {
            let (_, file_id) = self.add_file(&loc.filename());
            (file_id, loc.line() as u64, loc.col() as u64)
        };

        // Figure out whether the source changed.
        let source_changed = if let Some(last) = self.last_row_source.as_ref() {
            matches!(begin_end_block, Some(BeginEndBlock::ForceLine))
                || source_file != last.filename
                || line != last.line
                || col != last.col
        } else {
            true
        };

        let new_last_row = if let Some(last_row) = &self.last_row_source
            && !source_changed
        {
            last_row.clone()
        } else {
            DwarfLineRow {
                filename: source_file.clone(),
                line,
                col,
            }
        };

        let control_flow_or_dispatch = matches!(
            instr,
            Instr::B(_)
                | Instr::Bl(_)
                | Instr::Bx(_)
                | Instr::Blx(_)
                | Instr::Swi(_)
                | Instr::SwiEq(_)
        );

        let is_statement = addr == self.seq_addr_start
            || begin_end_block.is_some()
            || source_changed
            || control_flow_or_dispatch;

        if is_statement || control_flow_or_dispatch || source_changed {
            let unit = self.dwarf.units.get_mut(self.unit_id);
            let row = unit.line_program.row();
            row.address_offset = (addr - self.seq_addr_start) as u64;
            row.file = file_id;
            row.line = line;
            row.column = col;
            row.is_statement = is_statement;
            row.basic_block = begin_end_block == Some(BeginEndBlock::BeginBlock);
            unit.line_program.generate_row();

            self.last_row_source = Some(new_last_row);
        }
    }

    pub fn start(&mut self, addr: usize) {
        let unit = self.dwarf.units.get_mut(self.unit_id);
        self.seq_addr_start = addr;
        self.last_row_source = None;
        self.last_statement_source_line = None;
        unit.line_program.begin_sequence(Some(Address::Constant(
            (addr + self.target_addr as usize) as u64,
        )));
    }

    pub fn end(&mut self, addr: usize) {
        let unit = self.dwarf.units.get_mut(self.unit_id);
        unit.line_program
            .end_sequence((addr - self.seq_addr_start) as u64);
    }

    fn match_function(&self, label: &str) -> Option<(String, String)> {
        let symbol_hash = if let Some(stripped) = label.strip_prefix('_') {
            let hash = stripped
                .chars()
                .take_while(|c| *c != '_')
                .collect::<String>();
            if self.symbol_table.contains_key(&hash) {
                Some(hash)
            } else {
                None
            }
        } else {
            self.symbol_table
                .iter()
                .find(|(hash, name)| {
                    *name == label
                        && hash.len() == 64
                        && hash.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
                })
                .map(|(hash, _)| hash.clone())
        };
        if let Some(symbol_hash) = symbol_hash {
            let mut stripped = symbol_hash.as_bytes().to_vec();
            let name = self
                .symbol_table
                .get(&symbol_hash)
                .cloned()
                .unwrap_or_else(|| label.to_string());
            let mut left_stripped = stripped.clone();
            left_stripped.append(&mut b"_left_env".to_vec());
            let left_env = if let Some(res) = self
                .symbol_table
                .get(&String::from_utf8_lossy(&left_stripped).to_string())
                .cloned()
            {
                res == "1"
            } else {
                false
            };
            stripped.append(&mut b"_arguments".to_vec());
            let args = self
                .symbol_table
                .get(&String::from_utf8_lossy(&stripped).to_string())
                .map(|s| {
                    if left_env {
                        format!("(() . {s})")
                    } else {
                        s.to_string()
                    }
                })
                .unwrap_or_else(|| "ENV".to_string());
            return Some((name, args));
        }

        None
    }

    fn add_arguments<C: CreateSExp>(
        &mut self,
        subprogram_id: UnitEntryId,
        locations: &[VariableLocationInfo],
        here: Number,
        path: Number,
        args: C::S,
    ) {
        match args.explode() {
            SExpValue::Cons(a, b) => {
                self.add_arguments::<C>(
                    subprogram_id,
                    locations,
                    here.clone() << 1,
                    path.clone(),
                    a,
                );
                self.add_arguments::<C>(
                    subprogram_id,
                    locations,
                    here.clone() << 1,
                    path | here,
                    b,
                );
            }
            SExpValue::Atom(a) => {
                let argname = &String::from_utf8_lossy(&a).to_string();
                let unit = self.dwarf.units.get_mut(self.unit_id);

                let mut loclist = Vec::new();

                for l in locations.iter() {
                    let mut expr = (l.start_expr)();

                    let mut i = bi_one();
                    while i < here {
                        if (path.clone() & i.clone()) != bi_zero() {
                            expr.op_plus_uconst(4);
                        }
                        expr.op_deref();
                        i <<= 1;
                    }

                    loclist.push(Location::StartEnd {
                        begin: Address::Constant(l.beginning),
                        end: Address::Constant(l.end),
                        data: expr,
                    });
                }

                let loc_list_id = unit.locations.add(LocationList(loclist));

                let at_id = unit.add(subprogram_id, DW_TAG_formal_parameter);
                let at_ent = unit.get_mut(at_id);
                at_ent.set(
                    DW_AT_name,
                    AttributeValue::String(argname.as_bytes().to_vec()),
                );
                at_ent.set(DW_AT_type, AttributeValue::UnitRef(self.pointer_type));
                at_ent.set(DW_AT_location, AttributeValue::LocationListRef(loc_list_id));

                /*
                let at_id2 = unit.add(subprogram_id, DW_TAG_variable);
                let at_ent = unit.get_mut(at_id2);
                at_ent.set(
                    DW_AT_name,
                    AttributeValue::String(argname.as_bytes().to_vec()),
                );
                at_ent.set(DW_AT_type, AttributeValue::UnitRef(self.pointer_type));
                */
            }
            _ => {}
        }
    }

    // Create dwarf traffic needed to ensure that gdb can find the locals.
    pub fn decorate_function<C: CreateSExp>(
        &mut self,
        creator: &mut C,
        label: &str,
        addr: usize,
        size: usize,
        sexp: C::S,
        preferred_name: Option<&String>,
    ) -> Option<String> {
        let mut fde = FrameDescriptionEntry::new(
            Address::Constant((self.target_addr as usize + addr) as u64),
            size as u32,
        );
        // Function prolog:
        //   push {fp, lr}
        //   add  fp, sp, #4
        //   sub  sp, sp, #0x18
        //
        // Function epilog:
        //   sub  sp, fp, #4
        //   pop  {fp, lr}
        //   bx   lr
        //
        // The canonical frame address tracks caller SP through the body:
        // CFA = fp + 4. Saved FP/LR are at CFA-8/CFA-4.
        fde.add_instruction(4, CallFrameInstruction::Cfa(Arm::R13, 8));
        fde.add_instruction(4, CallFrameInstruction::Offset(Arm::R11, -8));
        fde.add_instruction(4, CallFrameInstruction::Offset(Arm::R14, -4));
        fde.add_instruction(8, CallFrameInstruction::Cfa(Arm::R11, 4));
        // After `pop {fp, lr}` and before `bx lr`, execution has returned to the
        // entry-state calling convention for this frame.
        let post_pop_offset = (size.saturating_sub(4)) as u32;
        fde.add_instruction(post_pop_offset, CallFrameInstruction::Cfa(Arm::R13, 0));
        fde.add_instruction(post_pop_offset, CallFrameInstruction::Restore(Arm::R11));
        fde.add_instruction(post_pop_offset, CallFrameInstruction::Restore(Arm::R14));
        let cfi_cie_id = self
            .cfi_cie_id
            .expect("CFI CIE should be initialized for unwind info");
        self.frame_table.add_fde(cfi_cie_id, fde);

        let matched_signature = self.match_function(label);
        let name = preferred_name
            .cloned()
            .or_else(|| matched_signature.clone().map(|(name, _)| name.clone()))
            .unwrap_or_else(|| format!("{sexp}"));
        let args = matched_signature
            .as_ref()
            .map(|(_, args)| args.clone())
            .unwrap_or_else(|| "ENV".to_string());

        // We'll make 3 subprograms to represent where the current arguments can be arrived
        // at from, then decorate all of them with the argument retriever below.

        let subprogram_names = [name.clone()];
        let subprogram_ids = {
            let unit = self.dwarf.units.get_mut(self.unit_id);
            let mut subprogram_ids = Vec::with_capacity(subprogram_names.len());
            for subprogram_name in subprogram_names.iter() {
                let subprogram_id = unit.add(unit.root(), DW_TAG_subprogram);

                // Frame pointer for the function.
                let mut fbexpr_mid = Expression::new();
                fbexpr_mid.op_breg(gimli::Register(13), 0);
                let loclist = vec![Location::StartEnd {
                    begin: Address::Constant(addr as u64),
                    end: Address::Constant((addr + size) as u64),
                    data: fbexpr_mid,
                }];
                let loc_list_id = unit.locations.add(LocationList(loclist));
                let sub_ent = unit.get_mut(subprogram_id);
                sub_ent.set(
                    DW_AT_name,
                    AttributeValue::String(subprogram_name.as_bytes().to_vec()),
                );
                sub_ent.set(DW_AT_type, AttributeValue::UnitRef(self.pointer_type));
                sub_ent.set(
                    DW_AT_low_pc,
                    AttributeValue::Address(Address::Constant(
                        (self.target_addr as usize + addr) as u64,
                    )),
                );
                sub_ent.set(
                    DW_AT_high_pc,
                    AttributeValue::Address(Address::Constant(
                        (self.target_addr as usize + addr + size) as u64,
                    )),
                );
                sub_ent.set(
                    DW_AT_frame_base,
                    AttributeValue::LocationListRef(loc_list_id),
                );
                subprogram_ids.push(subprogram_id);
            }
            subprogram_ids
        };
        let srcloc = creator.start_srcloc("*args*");
        if let Ok(parsed) = creator.parse_sexp(srcloc, args.bytes()) {
            let self_u32_type = self.u32_type;
            let early_reg_closure = move || {
                let mut early_reg_expr = Expression::new();
                early_reg_expr.op_regval_type(gimli::Register(7), self_u32_type);
                early_reg_expr
            };
            let frame_closure = || {
                let mut frame_expr = Expression::new();
                frame_expr.op_fbreg(12);
                frame_expr.op_deref();
                frame_expr
            };

            let locations = vec![
                VariableLocationInfo {
                    beginning: addr as u64,
                    end: addr as u64 + 0x1c,
                    start_expr: &early_reg_closure,
                },
                VariableLocationInfo {
                    beginning: addr as u64 + 0x1c,
                    end: (addr + size) as u64 - 2 * 4,
                    start_expr: &frame_closure,
                },
                VariableLocationInfo {
                    beginning: (addr + size) as u64 - 2 * 4,
                    end: (addr + size) as u64,
                    start_expr: &early_reg_closure,
                },
            ];
            if !parsed.is_empty() {
                for subprogram_id in subprogram_ids.iter().copied() {
                    self.add_arguments::<C>(
                        subprogram_id,
                        &locations,
                        bi_one(),
                        bi_zero(),
                        parsed[0].clone(),
                    );
                }
            }
        }

        Some(name.clone())
    }

    fn write_section(
        &self,
        name: &str,
        section: &dyn Section<DwarfSectionWriter>,
        instrs: &mut Vec<Instr>,
    ) {
        instrs.push(Instr::Align4);
        instrs.push(Instr::Section(name.to_string()));
        instrs.push(Instr::Bytes(section.written.clone()));
    }

    pub fn write(
        &mut self,
        current_addr: usize,
        instrs: &mut Vec<Instr>,
    ) -> gimli::write::Result<()> {
        let unit = self.dwarf.units.get_mut(self.unit_id);
        let unit_ent = unit.get_mut(unit.root());
        unit_ent.set(
            DW_AT_high_pc,
            AttributeValue::Address(Address::Constant(
                self.target_addr as u64 + current_addr as u64,
            )),
        );

        let mut sections = Sections::<DwarfSectionWriter>::default();
        self.dwarf.write(&mut sections)?;
        self.frame_table
            .write_debug_frame(&mut sections.debug_frame)?;
        self.frame_table.write_eh_frame(&mut sections.eh_frame)?;

        self.write_section(".debug_abbrev", &sections.debug_abbrev, instrs);
        self.write_section(".debug_info", &sections.debug_info, instrs);
        self.write_section(".debug_line", &sections.debug_line, instrs);
        self.write_section(".debug_line_str", &sections.debug_line_str, instrs);
        self.write_section(".debug_ranges", &sections.debug_ranges, instrs);
        self.write_section(".debug_rnglists", &sections.debug_rnglists, instrs);
        self.write_section(".debug_loc", &sections.debug_loc, instrs);
        self.write_section(".debug_loclists", &sections.debug_loclists, instrs);
        self.write_section(".debug_str", &sections.debug_str, instrs);
        self.write_section(".debug_frame", &sections.debug_frame, instrs);
        self.write_section(".eh_frame", &sections.eh_frame, instrs);

        Ok(())
    }
}
