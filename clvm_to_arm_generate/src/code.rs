use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::mem::swap;
use std::rc::Rc;
use std::str::FromStr;

use faerie::{ArtifactBuilder, Decl, Link, SectionKind};
use target_lexicon::triple;

use crate::arm::{BeginEndBlock, Encodable, Instr, Register};
use crate::dwarf::DwarfBuilder;
use crate::loader::ElfLoader;
use crate::mem::write_u32;
use crate::sexp::{CreateSExp, SExp, SExpValue, Srcloc, dequote, is_atom, is_wrapped_atom};
use crate::shatree::find_all_by_hash;

pub const NEXT_ALLOC_OFFSET: i32 = 0;

pub const SWI_DONE: usize = 0;
pub const SWI_THROW: usize = 1;
pub const SWI_DISPATCH_NEW_CODE: usize = 2;
pub const SWI_DISPATCH_INSTRUCTION: usize = 3;
pub const SWI_PRINT_EXPR: usize = 4;

pub const TARGET_ADDR: u32 = 0x1000;

pub struct ElfObject {
    pub object_file: Vec<u8>,
}

//
// Compile each program to clvm, then decompose into arm assembly.
// If it isn't a proper program, just translate it as clvm.
//
// Initially do this with binutils then later with internally linked libraries.
//
// It's easy enough to run:
//
// - main.s -
// .align 4
//
//     .globl test
//     .globl _start
//
//     _start:
//     add   sp, sp, #0x7000
//     push	{fp, lr}
//     add	fp, sp, #4
//     sub	sp, sp, #8
//     mov	r0, #5
//     bl	test
//     str	r0, [fp, #-8]
//     ldr	r3, [fp, #-8]
// #   mov	r0, r3
//     sub	sp, fp, #4
//     pop	{fp, lr}
//     bx	lr
//
// linked with
//
// - test.c -
// int test(int x) {
//     return x + 3;
// }
//
// in an arm system emulator.  we can link one in rust via armv4t_emu or run with
//
// qemu-system-arm -S -s -machine virt -device loader,addr=0x8000,file=./test-prog,cpu-num=0
//
// after building like
// arm-none-eabi-as -o main.o main.s
// arm-none-eabi-gcc -c test.c
// arm-none-eabi-gcc -Ttext=0x8000 -static -nostdlib -o test-prog main.o test.o
//
// We can execute _start at 0x8000 and have the stack at 0x7000 in this scenario.
//
// CLVM operators will take a 'self' object pointer in r0, which will contain a
// pointer to the environment stack at the 0th offset, a pointer to the function
// table and pointers to other utilities, including a function which translates
// and runs untranslated CLVM, along with sending an event to gdb to load any
// symbols it's able to generate if possible.
//
// We'll have a table that contains the functions that were recovered from the
// provided CLVM and chialisp inputs.  Given the treehash of some upcoming code
// in the translation of an 'a' operation, we'll check whether we've cached the
// treehash by address (because each clvm value is written only once), then
// treehash and cache the translation, then jump to either the function which
// comes from the matching treehash or the emulator function.
//
// The entrypoint of the code contains a pointer to the actual environment, which
// is copied into the heap and then the main object is constructed around it.

// Aranges:
// I'm unsure if gimli can write this by itself.
// For now I'm going to generate it myself.
//
// Format:
// Header --
// WORD remaining section size
// HALF dwarf version
// WORD .info offset
// BYTE bytes per address (n)
// Then a sequence of tuples after padding to n bytes --
// n-addr Start Address
// n-uint Length

enum Constant {
    Atom(String, Vec<u8>),
    Cons(String, String, String),
}

impl Constant {
    fn label(&self) -> String {
        match self {
            Constant::Atom(lbl, _) => lbl.clone(),
            Constant::Cons(lbl, _, _) => lbl.clone(),
        }
    }
}

pub struct WaitingProgram<C: CreateSExp> {
    label: String,
    sexp: C::S,
    parent: Option<Rc<WaitingProgram<C>>>,
}

pub struct Program<C: CreateSExp> {
    target_addr: u32,
    finished_insns: Vec<Instr>,
    first_label: String,
    env_label: String,
    encounters_of_code: HashMap<Vec<u8>, usize>,
    labels_by_hash: HashMap<Vec<u8>, String>,
    code_to_hash: HashMap<String, String>,
    waiting_programs: Vec<Rc<WaitingProgram<C>>>,
    constants: HashMap<Vec<u8>, Constant>,
    symbol_table: Rc<HashMap<String, String>>,
    current_symbol: String,
    current_symbol_name: Option<String>,
    function_symbols: HashMap<String, String>,
    renamed_symbols: HashMap<String, String>,
    defined_with_name: HashMap<String, String>,
    start_addr: usize,
    current_addr: usize,
    dwarf_builder: DwarfBuilder,
}

impl<C: CreateSExp> fmt::Display for Program<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let write_vec = |f: &mut Formatter, v: &[Instr]| -> fmt::Result {
            for i in v.iter() {
                writeln!(f, "{i}")?;
            }
            Ok(())
        };

        write_vec(f, &self.finished_insns)
    }
}

fn hexify(v: &[u8]) -> String {
    hex::encode(v)
}

fn write_u16_le(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset] = (value & 0xff) as u8;
    buf[offset + 1] = (value >> 8) as u8;
}

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    (buf[offset] as u32)
        | ((buf[offset + 1] as u32) << 8)
        | ((buf[offset + 2] as u32) << 16)
        | ((buf[offset + 3] as u32) << 24)
}

fn mark_elf_executable(buf: &mut [u8], entry: u32) -> Result<(), String> {
    const ELF_MAGIC: &[u8] = b"\x7fELF";
    const EI_CLASS: usize = 4;
    const EI_DATA: usize = 5;
    const ELFCLASS32: u8 = 1;
    const ELFDATA2LSB: u8 = 1;
    const E_TYPE: usize = 16;
    const E_ENTRY: usize = 24;
    const ET_EXEC: u16 = 2;

    if buf.len() < 52
        || &buf[..ELF_MAGIC.len()] != ELF_MAGIC
        || buf[EI_CLASS] != ELFCLASS32
        || buf[EI_DATA] != ELFDATA2LSB
    {
        return Err("expected 32-bit little-endian ELF output".to_string());
    }

    write_u16_le(buf, E_TYPE, ET_EXEC);
    write_u32(buf, E_ENTRY, entry);
    Ok(())
}

fn add_elf_load_segment(buf: &mut Vec<u8>) -> Result<(), String> {
    const E_PHOFF: usize = 28;
    const E_SHOFF: usize = 32;
    const E_PHENTSIZE: usize = 42;
    const E_PHNUM: usize = 44;
    const E_SHENTSIZE: usize = 46;
    const E_SHNUM: usize = 48;
    const SH_ADDR: usize = 12;
    const SH_OFFSET: usize = 16;
    const SH_SIZE: usize = 20;
    const SH_FLAGS: usize = 8;
    const SHF_ALLOC: u32 = 2;
    const PT_LOAD: u32 = 1;
    const PF_X: u32 = 1;
    const PF_W: u32 = 2;
    const PF_R: u32 = 4;

    if buf.len() < 52 {
        return Err("ELF header too short".to_string());
    }

    let shoff = read_u32_le(buf, E_SHOFF) as usize;
    let shentsize = u16::from_le_bytes([buf[E_SHENTSIZE], buf[E_SHENTSIZE + 1]]) as usize;
    let shnum = u16::from_le_bytes([buf[E_SHNUM], buf[E_SHNUM + 1]]) as usize;
    let phentsize = u16::from_le_bytes([buf[E_PHENTSIZE], buf[E_PHENTSIZE + 1]]) as usize;
    if phentsize != 32 {
        return Err(format!(
            "expected ELF32 program header size 32, got {phentsize}"
        ));
    }

    let mut min_addr = u32::MAX;
    let mut max_addr = 0_u32;
    let mut min_offset = u32::MAX;
    let mut max_offset = 0_u32;
    for section_idx in 0..shnum {
        let section = shoff + section_idx * shentsize;
        if section + SH_SIZE + 4 > buf.len() {
            return Err("section header table extends past ELF buffer".to_string());
        }
        let flags = read_u32_le(buf, section + SH_FLAGS);
        if flags & SHF_ALLOC == 0 {
            continue;
        }

        let addr = read_u32_le(buf, section + SH_ADDR);
        let offset = read_u32_le(buf, section + SH_OFFSET);
        let size = read_u32_le(buf, section + SH_SIZE);
        min_addr = min_addr.min(addr);
        max_addr = max_addr.max(addr + size);
        min_offset = min_offset.min(offset);
        max_offset = max_offset.max(offset + size);
    }

    if min_addr == u32::MAX {
        return Err("no allocatable sections found for PT_LOAD".to_string());
    }

    let phoff = buf.len();
    buf.resize(phoff + phentsize, 0);
    write_u32(buf, phoff, PT_LOAD);
    write_u32(buf, phoff + 4, min_offset);
    write_u32(buf, phoff + 8, min_addr);
    write_u32(buf, phoff + 12, min_addr);
    write_u32(buf, phoff + 16, max_offset - min_offset);
    write_u32(buf, phoff + 20, max_addr - min_addr);
    write_u32(buf, phoff + 24, PF_R | PF_W | PF_X);
    write_u32(buf, phoff + 28, 0x1000);
    write_u32(buf, E_PHOFF, phoff as u32);
    write_u16_le(buf, E_PHNUM, 1);
    Ok(())
}

pub fn swi_print(register: usize, label: usize) -> usize {
    SWI_PRINT_EXPR | register << 4 | label << 8
}

fn choose_location<C: CreateSExp>(
    creator: &C,
    sexp: C::S,
    parent: Option<Rc<WaitingProgram<C>>>,
) -> (C::S, C::SL) {
    let this_loc = creator.loc(sexp.clone());
    let filename = this_loc.filename();
    let last_component_offset = filename.find('/').map(|a| a + 1).unwrap_or(0);
    let last_component = filename[last_component_offset..].to_string();

    if last_component.starts_with("*")
        && let Some(next) = parent
    {
        return choose_location(creator, next.sexp.clone(), next.parent.clone());
    }

    (sexp, this_loc)
}

impl<C: CreateSExp> Program<C> {
    fn get_renamed_name_for_label(&self, label: &str) -> Option<String> {
        let hash = label.strip_prefix('_').and_then(|s| s.split('_').next())?;
        self.renamed_symbols.get(hash).cloned()
    }

    fn get_code_label(&mut self, hash: &[u8]) -> String {
        let n = if let Some(n) = self.encounters_of_code.get(hash) {
            *n
        } else {
            0
        };

        self.encounters_of_code.insert(hash.to_vec(), n + 1);
        format!("_{}_{n}", hexify(hash))
    }

    fn do_throw(&mut self, loc: &C::SL, hash: &[u8]) {
        self.load_atom(loc, hash, hash);
        self.push(loc, Instr::Swi(SWI_PRINT_EXPR));
        self.push(loc, Instr::Swi(SWI_THROW));
    }

    fn add_sexp(&mut self, hash: &[u8], s: C::S) -> String {
        if let Some(lbl) = self.constants.get(hash) {
            return lbl.label();
        }

        match s.explode() {
            SExpValue::Cons(a, b) => {
                let a_hash = a.sha256tree();
                let b_hash = b.sha256tree();
                let a_label = self.add_sexp(&a_hash, a);
                let b_label = self.add_sexp(&b_hash, b);
                let label = format!("_{}", hexify(hash));
                self.constants.insert(
                    hash.to_vec(),
                    Constant::Cons(label.clone(), a_label.clone(), b_label.clone()),
                );
                label
            }
            _ => self.add_atom(
                hash,
                &s.atom_bytes::<C::S>()
                    .expect("non-cons debug sexp should atomize"),
            ),
        }
    }

    fn load_sexp(&mut self, loc: &C::SL, hash: &[u8], s: C::S) {
        let label = self.add_sexp(hash, s);
        self.push(loc, Instr::Lea(Register::R(0), label));
    }

    fn first_rest(
        &mut self,
        parent: Option<Rc<WaitingProgram<C>>>,
        loc: &C::SL,
        hash: &[u8],
        lst: &[C::S],
        offset: i32,
    ) {
        if lst.len() != 1 {
            return self.do_throw(loc, hash);
        }

        let subexp = self.add(parent.clone(), lst[0].clone());
        for i in &[
            Instr::Addi(Register::R(0), Register::R(7), 0),
            // Determine if the result is a cons.
            Instr::Bl(subexp),
            Instr::Cmpi(Register::R(0), 0),
            Instr::SwiEq(SWI_THROW),
            Instr::Ldr(Register::R(1), Register::R(0), 0),
            Instr::Andi(Register::R(1), Register::R(1), 1),
            Instr::Cmpi(Register::R(1), 1),
            Instr::SwiEq(SWI_THROW),
            Instr::Ldr(Register::R(0), Register::R(0), offset),
        ] {
            self.push(loc, i.clone());
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn do_operator(
        &mut self,
        creator: &mut C,
        parent: Option<Rc<WaitingProgram<C>>>,
        loc: &C::SL,
        hash: &[u8],
        a: &[u8],
        b: C::S,
        treat_as_quoted: bool,
    ) {
        if treat_as_quoted {
            todo!();
        }

        if a == b"" {
            return self.do_throw(loc, hash);
        }

        // Quote is special.
        if a == [1] {
            self.add(parent.clone(), b.clone());
            let b_hash = b.sha256tree();
            return self.load_sexp(loc, &b_hash, b);
        }

        // Every other operator must have a proper list following it.
        let lst = if let Some(lst) = b.proper_list() {
            lst
        } else {
            return self.do_throw(loc, hash);
        };

        if a == [2] {
            // Apply operator
            if lst.len() != 2 {
                return self.do_throw(loc, hash);
            }

            let env_comp = self.add(parent.clone(), lst[1].clone());
            for i in &[
                Instr::Addi(Register::R(0), Register::R(7), 0),
                Instr::Bl(env_comp),
                Instr::Addi(Register::R(4), Register::R(0), 0),
            ] {
                self.push(loc, i.clone());
            }

            if let Some(quoted_code) = dequote(lst[0].clone()) {
                // Short circuit by reading out the quoted code and running it.
                let quoted = self.add(parent.clone(), quoted_code.clone());

                for i in &[
                    Instr::Addi(Register::R(7), Register::R(4), 0),
                    Instr::Addi(Register::R(0), Register::R(7), 0),
                    Instr::Bl(quoted),
                ] {
                    self.push(loc, i.clone());
                }
            } else {
                let code_comp = self.add(parent.clone(), lst[0].clone());

                for i in &[
                    Instr::Addi(Register::R(0), Register::R(7), 0),
                    Instr::Bl(code_comp),
                    Instr::Addi(Register::R(7), Register::R(4), 0),
                    Instr::Swi(SWI_DISPATCH_NEW_CODE),
                    Instr::Bx(Register::R(1)),
                ] {
                    self.push(loc, i.clone());
                }
            }

            self.push(loc, Instr::Ldr(Register::R(7), Register::SP, 12));
        } else if a == [3] {
            // If operator
            if lst.len() != 3 {
                return self.do_throw(loc, hash);
            }

            let else_clause = self.add(parent.clone(), lst[2].clone());
            let then_clause = self.add(parent.clone(), lst[1].clone());
            let cond_clause = self.add(parent.clone(), lst[0].clone());

            for i in &[
                Instr::Addi(Register::R(0), Register::R(7), 0),
                Instr::Bl(else_clause),
                Instr::Addi(Register::R(6), Register::R(0), 0),
                Instr::Addi(Register::R(0), Register::R(7), 0),
                Instr::Bl(then_clause),
                Instr::Addi(Register::R(4), Register::R(0), 0),
                Instr::Addi(Register::R(0), Register::R(7), 0),
                Instr::Bl(cond_clause),
                Instr::Cmpi(Register::R(0), 0),
                Instr::AddiEq(Register::R(4), Register::R(6), 0),
                Instr::Ldr(Register::R(1), Register::R(0), 0),
                Instr::Cmpi(Register::R(1), 1),
                Instr::AddiEq(Register::R(4), Register::R(6), 0),
                Instr::Addi(Register::R(0), Register::R(4), 0),
            ] {
                self.push(loc, i.clone());
            }
        } else if a == [4] {
            // Cons operator
            if lst.len() != 2 {
                return self.do_throw(loc, hash);
            }

            let rest_label = self.add(parent.clone(), lst[1].clone());
            let first_label = self.add(parent.clone(), lst[0].clone());

            for i in &[
                Instr::Addi(Register::R(0), Register::R(7), 0),
                Instr::Bl(rest_label),
                Instr::Addi(Register::R(4), Register::R(0), 0),
                Instr::Addi(Register::R(0), Register::R(7), 0),
                Instr::Bl(first_label),
                // R1 = next allocated address.
                Instr::Ldr(Register::R(1), Register::R(5), NEXT_ALLOC_OFFSET),
                // R2 = R1 + 8 (size of cons)
                Instr::Addi(Register::R(2), Register::R(1), 8),
                Instr::Str(Register::R(2), Register::R(5), NEXT_ALLOC_OFFSET),
                // Build cons
                Instr::Str(Register::R(0), Register::R(1), 0),
                Instr::Str(Register::R(4), Register::R(1), 4),
                // Move the result to r0
                Instr::Addi(Register::R(0), Register::R(1), 0),
            ] {
                self.push(loc, i.clone());
            }
        } else if a == [5] {
            self.first_rest(parent.clone(), loc, hash, &lst, 0)
        } else if a == [6] {
            self.first_rest(parent.clone(), loc, hash, &lst, 4)
        } else {
            // Ensure we have this sexp loadable as data.
            let operator_sexp = creator.atom(loc.clone(), a);
            let atom_hash = operator_sexp.sha256tree();
            let label = self.add_atom(&atom_hash, a);

            // Load a nil into R4.
            self.push(loc, Instr::Andi(Register::R(4), Register::R(4), 0));

            // For each subexpression, call it and replace R4 with (cons R0 R4)
            for item in lst.iter().rev() {
                let clause_label = self.add(parent.clone(), item.clone());
                for i in &[
                    // Load the allocator ptr into R0.
                    Instr::Ldr(Register::R(0), Register::R(5), NEXT_ALLOC_OFFSET),
                    // Allocate a cons (new addr in R6)
                    Instr::Addi(Register::R(6), Register::R(0), 8),
                    // Store back the pointer.
                    Instr::Str(Register::R(6), Register::R(5), NEXT_ALLOC_OFFSET),
                    // R6 = alloc ptr
                    Instr::Addi(Register::R(6), Register::R(0), 0),
                    // Reload R0 with the env ptr.
                    Instr::Addi(Register::R(0), Register::R(7), 0),
                    // Call the arg code
                    Instr::Bl(clause_label),
                    // Store R0 into the cons.
                    Instr::Str(Register::R(0), Register::R(6), 0),
                    // Store R4 into the cons.
                    Instr::Str(Register::R(4), Register::R(6), 4),
                    // Replace R4 with R6 (the new cons)
                    Instr::Addi(Register::R(4), Register::R(6), 0),
                ] {
                    self.push(loc, i.clone());
                }
            }

            for i in &[
                // Load the sexp for the operator into R0
                Instr::Lea(Register::R(0), label),
                // Set R1 to the tail exp.
                Instr::Addi(Register::R(1), Register::R(4), 0),
                // Call to do the operator.
                Instr::Swi(SWI_DISPATCH_INSTRUCTION),
            ] {
                self.push(loc, i.clone());
            }
        }
    }

    // R0 = the address of the env block.
    fn env_select(&mut self, loc: &C::SL, hash: &[u8], v: &[u8]) {
        if v.is_empty() {
            self.load_atom(loc, hash, v);
            return;
        }

        // Let r0 be our pointer.
        self.push(loc, Instr::Addi(Register::R(0), Register::R(7), 0));

        // Whole env ref.
        if v == [1] {
            return;
        }

        for (i, byt) in v.iter().enumerate().rev() {
            for bit in 0..8 {
                let remaining = byt >> bit;
                if remaining == 1 && i == 0 {
                    // We have the right value.
                    return;
                } else {
                    let offset = ((remaining & 1) * 4) as i32;

                    for i in &[
                        // Check for a cons.
                        Instr::Cmpi(Register::R(0), 0),
                        Instr::SwiEq(SWI_THROW),
                        Instr::Ldr(Register::R(1), Register::R(0), 0),
                        Instr::Andi(Register::R(1), Register::R(1), 1),
                        Instr::Cmpi(Register::R(1), 1),
                        // Break if it was an atom.
                        Instr::SwiEq(SWI_THROW),
                        // Load if it was a cons.
                        Instr::Ldr(Register::R(0), Register::R(0), offset),
                    ] {
                        self.push(loc, i.clone());
                    }
                }
            }
        }
    }

    fn add_atom(&mut self, hash: &[u8], v: &[u8]) -> String {
        if let Some(lbl) = self.constants.get(hash) {
            return lbl.label();
        }

        let label = format!("_{}", hexify(hash));
        self.constants
            .insert(hash.to_vec(), Constant::Atom(label.clone(), v.to_vec()));
        label
    }

    fn load_atom(&mut self, loc: &C::SL, hash: &[u8], v: &[u8]) {
        let label = self.add_atom(hash, v);
        self.push(loc, Instr::Lea(Register::R(0), label));
    }

    fn add(&mut self, parent: Option<Rc<WaitingProgram<C>>>, sexp: C::S) -> String {
        let hash = sexp.sha256tree();
        if let Some(existing_label) = self.labels_by_hash.get(&hash) {
            return existing_label.clone();
        }

        // Note: get_code_label issues a fresh label for this hash every time.
        let body_label = self.get_code_label(&hash);

        self.code_to_hash
            .insert(sexp.to_string(), body_label.clone());
        self.labels_by_hash.insert(hash, body_label.clone());
        self.waiting_programs.push(Rc::new(WaitingProgram {
            parent,
            label: body_label.clone(),
            sexp: sexp.clone(),
        }));
        body_label
    }

    fn push_be(&mut self, srcloc: &C::SL, instr: Instr, begin_end_block: Option<BeginEndBlock>) {
        let size = instr.size(self.current_addr);

        self.finished_insns.push(instr.clone());
        let start_block = matches!(begin_end_block, Some(BeginEndBlock::BeginBlock));
        let end_block = matches!(begin_end_block, Some(BeginEndBlock::EndBlock));

        if start_block {
            self.current_addr = (self.current_addr + 15) & !15;
            self.start_addr = self.current_addr;
        }

        if size != 0 {
            let next_addr = self.current_addr + size;
            self.dwarf_builder.add_instr::<C>(
                self.current_addr,
                srcloc,
                instr.clone(),
                begin_end_block,
            );
            self.current_addr = next_addr;
        }

        if end_block {
            self.current_addr = (self.current_addr + 15) & !15;
        }
    }

    fn push(&mut self, srcloc: &C::SL, instr: Instr) {
        self.push_be(srcloc, instr, None);
    }

    fn emit_waiting(&mut self, creator: &mut C) {
        while let Some(waiting) = self.waiting_programs.pop() {
            let parent = Some(waiting.clone());
            let label = waiting.label.clone();
            let sexp = waiting.sexp.clone();
            let hash = sexp.sha256tree();
            let (anchor_sexp, location) =
                choose_location(creator, sexp.clone(), waiting.parent.clone());

            self.labels_by_hash.insert(hash.clone(), label.clone());
            self.current_symbol = label.clone();
            self.current_symbol_name = self.get_renamed_name_for_label(&label);

            self.dwarf_builder.start(self.current_addr);

            self.push(&location, Instr::Globl(label.clone()));
            self.push(&location, Instr::Label(label.clone()));

            self.push_be(
                &location,
                Instr::Push(vec![Register::FP, Register::LR]),
                Some(BeginEndBlock::BeginBlock),
            );
            for i in &[
                Instr::Addi(Register::FP, Register::SP, 4),
                Instr::Subi(Register::SP, Register::SP, 0x18),
                Instr::Str(Register::R(4), Register::SP, 0),
                Instr::Str(Register::R(5), Register::SP, 4),
                Instr::Str(Register::R(6), Register::SP, 8),
                Instr::Str(Register::R(7), Register::SP, 12),
                Instr::Addi(Register::R(7), Register::R(0), 0),
            ] {
                self.push(&location, i.clone());
            }

            self.push_be(
                &location,
                // Insert a nop we can land on before translating any interior expression.
                // This will allow any function or alias to contain an insruction apart from
                // other code generation for the purpose of breakpoints.
                Instr::Addi(Register::R(0), Register::R(0), 0),
                Some(BeginEndBlock::ForceLine),
            );

            // Translate body.
            match sexp.explode() {
                SExpValue::Cons(a, b) => {
                    if let Some(atom) = is_atom(a.clone()) {
                        // do quoted operator
                        self.do_operator(
                            creator,
                            parent,
                            &location,
                            &hash,
                            &atom,
                            b.clone(),
                            false,
                        );
                    } else if let Some((_, a)) = is_wrapped_atom(a.clone()) {
                        // do unquoted operator
                        self.do_operator(creator, parent, &location, &hash, &a, b.clone(), true);
                    } else {
                        // invalid head form, just throw.
                        self.do_throw(&location, &hash);
                    }
                }
                SExpValue::Nil => self.load_atom(&location, &hash, &[]),
                SExpValue::Atom(v) => {
                    if v.is_empty() {
                        self.load_atom(&location, &hash, &[])
                    } else {
                        self.env_select(&location, &hash, &v);
                    }
                }
            }

            for i in &[
                Instr::Ldr(Register::R(4), Register::SP, 0),
                Instr::Ldr(Register::R(5), Register::SP, 4),
                Instr::Ldr(Register::R(6), Register::SP, 8),
                Instr::Ldr(Register::R(7), Register::SP, 12),
                Instr::Subi(Register::SP, Register::FP, 4),
                Instr::Pop(vec![Register::FP, Register::LR]),
            ] {
                self.push(&location, i.clone());
            }

            self.push_be(
                &location,
                Instr::Bx(Register::LR),
                Some(BeginEndBlock::EndBlock),
            );

            self.dwarf_builder.end(self.current_addr);

            if let Some(function_name) = self.dwarf_builder.decorate_function(
                creator,
                &label,
                self.start_addr,
                self.current_addr - self.start_addr,
                anchor_sexp.clone(),
                self.current_symbol_name.as_ref(),
            ) {
                self.function_symbols.insert(label.clone(), function_name);
            }

            self.current_symbol_name = None;
        }
    }

    fn start_insns(&mut self, creator: &mut C) {
        let srcloc = C::SL::start("*prolog*");
        let source_sexp = creator.atom(srcloc.clone(), b"prolog");
        for i in &[
            Instr::Align4,
            Instr::Globl("_start".to_string()),
            Instr::Label("_start".to_string()),
        ] {
            self.push(&srcloc, i.clone());
        }

        self.push_be(
            &srcloc,
            Instr::Push(vec![Register::FP, Register::LR]),
            Some(BeginEndBlock::BeginBlock),
        );
        for i in &[
            Instr::Addi(Register::FP, Register::SP, 4),
            Instr::Subi(Register::SP, Register::SP, 0x18),
            Instr::Str(Register::R(4), Register::SP, 0),
            Instr::Str(Register::R(5), Register::SP, 4),
            Instr::Str(Register::R(6), Register::SP, 8),
            Instr::Str(Register::R(7), Register::SP, 12),
            // Load the env into r0 and the global data addr into r5.
            Instr::Lea(Register::R(5), "_run".to_string()),
            Instr::Ldr(Register::R(7), Register::R(5), 4),
            Instr::Addi(Register::R(0), Register::R(7), 0),
            // Call the program.
            Instr::Bl(self.first_label.clone()),
            // Print the last value.
            Instr::Swi(SWI_PRINT_EXPR),
            Instr::Swi(SWI_DONE),
        ] {
            self.push(&creator.loc(source_sexp.clone()), i.clone());
        }

        // Epilogue doesn't really matter since we did SWI_DONE, but it has symmetry
        // with other functions in the program.
        for i in &[
            Instr::Ldr(Register::R(4), Register::SP, 0),
            Instr::Ldr(Register::R(5), Register::SP, 4),
            Instr::Ldr(Register::R(6), Register::SP, 8),
            Instr::Ldr(Register::R(7), Register::SP, 12),
            Instr::Subi(Register::SP, Register::FP, 4),
            Instr::Pop(vec![Register::FP, Register::LR]),
        ] {
            self.push(&creator.loc(source_sexp.clone()), i.clone());
        }

        self.push_be(
            &creator.loc(source_sexp.clone()),
            Instr::Bx(Register::LR),
            Some(BeginEndBlock::EndBlock),
        );
    }

    fn finish_insns(&mut self) -> Result<(), String> {
        let srcloc = C::SL::start("*epilog*");
        let mut constants = HashMap::new();
        swap(&mut constants, &mut self.constants);

        for i in [
            Instr::Align4,
            Instr::Globl("_run".to_string()),
            Instr::Label("_run".to_string()),
            Instr::Long(0x10000000),
            Instr::Addr(self.env_label.clone(), true),
            // Write the constant data.
            Instr::Align4,
            Instr::Section(".data".to_string()),
        ]
        .iter()
        {
            self.push(&srcloc, i.clone());
        }

        for (_, c) in constants.iter() {
            match c {
                Constant::Cons(label, a_label, b_label) => {
                    for i in &[
                        Instr::Align4,
                        Instr::Globl(label.clone()),
                        Instr::Label(label.clone()),
                        Instr::Addr(a_label.clone(), false),
                        Instr::Addr(b_label.clone(), false),
                    ] {
                        self.push(&srcloc, i.clone());
                    }
                }
                Constant::Atom(label, bytes) => {
                    for i in &[
                        Instr::Align4,
                        Instr::Globl(label.clone()),
                        Instr::Label(label.clone()),
                        Instr::Long(bytes.len() * 2 + 1),
                        Instr::Bytes(bytes.clone()),
                    ] {
                        self.push(&srcloc, i.clone());
                    }
                }
            }
        }
        swap(&mut constants, &mut self.constants);

        // Capture mappings from function symbols to names (one per target).
        for i in self.finished_insns.iter() {
            if let Instr::Globl(defname) = i {
                // XXX When a bare symbol exists with no other information that
                // XXX matches the looked-up name, gdb can set a breakpoint in
                // XXX the containing block, which is the whole compilation unit
                // XXX in this case.  Revisit this when we know how to mark up
                // XXX the named symbol properly.
                if let Some(funname) = self.function_symbols.get(defname) {
                    self.defined_with_name
                        .insert(format!("_$_{funname}"), defname.clone());
                }

                let start = if defname.starts_with("_$_") {
                    Some(3)
                } else if defname.starts_with("_") {
                    Some(1)
                } else {
                    None
                };
                if let Some(start) = start
                    && defname.len() >= start + 64
                {
                    let stripped_symbol = &defname[start..(start + 64)];
                    if let Some(funname) = self.symbol_table.get(stripped_symbol) {
                        self.defined_with_name
                            .insert(funname.clone(), funname.clone());
                    }
                }
            }
        }

        self.dwarf_builder
            .write(self.current_addr, &mut self.finished_insns)
            .unwrap();

        Ok(())
    }

    pub fn to_elf(&self, output: &str) -> Result<ElfObject, String> {
        let mut sections = Vec::new();
        let mut obj = ArtifactBuilder::new(triple!("arm-unknown-unknown-unknown-elf"))
            .name(output.to_owned())
            .finish();
        // Collect declarations
        let mut waiting_for_debug_info = None;
        let mut data_section = false;
        let mut data = "".to_string();

        let mut decls: Vec<(String, Decl)> = self
            .finished_insns
            .iter()
            .filter_map(|i| {
                if let Instr::Section(name) = i {
                    if name.starts_with(".debug") || name.starts_with(".eh") {
                        waiting_for_debug_info = Some(name.clone());
                        data_section = false;
                        return Some((name.to_string(), Decl::section(SectionKind::Debug).into()));
                    } else {
                        waiting_for_debug_info = None;
                        data_section = true;
                        return None;
                    }
                } else if let Instr::Globl(name) = i {
                    if data_section {
                        data = name.clone();
                        return Some((data.clone(), Decl::data().global().into()));
                    } else {
                        return Some((name.to_string(), Decl::function().into()));
                    };
                } else if let Instr::Bytes(b) = i {
                    // Define section in the faerie way.
                    if let Some(waiting) = waiting_for_debug_info.clone() {
                        waiting_for_debug_info = None;
                        sections.push((waiting, b.clone()));
                    }
                }

                None
            })
            .collect();

        // Declare .debug_aranges
        decls.push((
            ".debug_aranges".to_string(),
            Decl::section(SectionKind::Debug).into(),
        ));

        obj.declarations(decls.into_iter())
            .map_err(|e| format!("{e:?}"))?;

        let mut relocations = Vec::new();
        let mut function_body = Vec::new();
        let mut in_function = None;

        let mut produced_code = 0;
        let mut handle_def_end =
            |function_body: &mut Vec<u8>, in_function: &mut Option<String>| -> Result<(), String> {
                if let Some(defname) = in_function.as_ref()
                    && !function_body.is_empty()
                {
                    let mut aligned_body = function_body.clone();
                    while !aligned_body.len().is_multiple_of(16) {
                        aligned_body.push(0);
                    }
                    produced_code += aligned_body.len();
                    obj.define(defname, aligned_body)
                        .map_err(|e| format!("{e:?}"))?;
                    *function_body = Vec::new();
                }

                Ok(())
            };

        for i in self.finished_insns.iter() {
            if let Instr::Globl(name) = &i {
                handle_def_end(&mut function_body, &mut in_function)?;
                in_function = Some(name.to_string());
            }

            if let Some(f) = in_function.as_ref() {
                i.encode(&mut function_body, &mut relocations, f);
            }
        }

        handle_def_end(&mut function_body, &mut in_function)?;
        // Create .debug_aranges
        let mut debug_aranges: Vec<u8> = (0..0x20).map(|_| 0).collect();
        write_u32(&mut debug_aranges, 0, 0x1c);
        debug_aranges[4] = 2;
        write_u32(&mut debug_aranges, 6, 0);
        debug_aranges[10] = 4;
        write_u32(&mut debug_aranges, 16, self.target_addr);
        write_u32(&mut debug_aranges, 20, produced_code as u32);
        sections.push((".debug_aranges".to_string(), debug_aranges));

        for (name, bytes) in sections.iter() {
            obj.define(name, bytes.clone())
                .map_err(|e| format!("{e:?}"))?;
        }

        for r in relocations.iter() {
            let resolved_target = if let Some(code_to_hash) = self.code_to_hash.get(&r.reloc_target)
            {
                code_to_hash.clone()
            } else {
                r.reloc_target.clone()
            };

            obj.link(Link {
                from: &r.function,
                to: &resolved_target,
                at: r.code_location as u64,
            })
            .map_err(|e| format!("link {e:?}"))?;
        }

        let mut result_buf = obj.emit().map_err(|e| format!("obj emit {e:?}"))?;
        mark_elf_executable(&mut result_buf, self.target_addr)?;

        // Patch up
        let create_patches = |result_buf: &mut [u8]| {
            let elf_loader = ElfLoader::new(result_buf, self.target_addr).expect("should load");
            elf_loader.patch_sections()
        };

        let patches = create_patches(&mut result_buf);

        for (target, value) in patches.into_iter() {
            write_u32(&mut result_buf, target, value);
        }

        add_elf_load_segment(&mut result_buf)?;

        Ok(ElfObject {
            object_file: result_buf,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        creator: &mut C,
        program: HashMap<String, C::SL>,
        filename: &str,
        sexp: C::S,
        env: C::S,
        target_addr: u32,
        symbol_table: Rc<HashMap<String, String>>,
    ) -> Result<Self, String> {
        let remap_hashes: Vec<_> = symbol_table
            .iter()
            .filter_map(|(hash, name)| {
                if name.contains(':') || name.contains('_') || name == "source_file" {
                    return None;
                }
                if !program.contains_key(name) {
                    return None;
                }

                if let Ok(byte_hash) = hex::decode(hash) {
                    let all_matches = find_all_by_hash(&byte_hash, sexp.clone());
                    let selected = if let Some(target_loc) = program.get(name) {
                        all_matches
                            .iter()
                            .find(|matched| {
                                let matched_ref: &C::S = matched;
                                let matched_clone: C::S = matched_ref.clone();
                                target_loc.overlap(&creator.loc(matched_clone))
                            })
                            .cloned()
                    } else {
                        None
                    }
                    .or_else(|| all_matches.first().cloned());
                    if let Some(selected) = selected {
                        return Some((byte_hash, name.clone(), selected));
                    }
                }
                None
            })
            .collect();

        let dwarf_builder = DwarfBuilder::new(filename, target_addr, symbol_table.clone());
        let mut p: Program<C> = Program {
            finished_insns: Vec::new(),
            first_label: Default::default(),
            env_label: Default::default(),
            encounters_of_code: Default::default(),
            labels_by_hash: Default::default(),
            code_to_hash: Default::default(),
            waiting_programs: Default::default(),
            constants: Default::default(),
            symbol_table: Default::default(),
            function_symbols: Default::default(),
            renamed_symbols: Default::default(),
            defined_with_name: Default::default(),
            current_addr: 0,
            start_addr: 0,
            target_addr,
            current_symbol: "_start".to_string(),
            current_symbol_name: None,
            dwarf_builder,
        };

        p.symbol_table = symbol_table;
        let envhash = sexp.sha256tree();
        for (remap_hash, name, remap_sexp) in remap_hashes.into_iter() {
            let remap_hash_hex = hex::encode(&remap_hash);
            p.renamed_symbols
                .insert(remap_hash_hex.clone(), name.clone());
            p.add_sexp(&remap_hash, remap_sexp.clone());
        }
        p.first_label = p.add(None, sexp.clone());
        p.start_insns(creator);
        p.env_label = p.add_sexp(&envhash, env);
        while !p.waiting_programs.is_empty() {
            p.emit_waiting(creator);
        }
        p.finish_insns()?;
        Ok(p)
    }
}
