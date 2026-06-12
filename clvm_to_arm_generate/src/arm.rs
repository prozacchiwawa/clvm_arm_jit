use std::fmt;
use std::fmt::Formatter;

#[derive(Clone, Debug)]
pub enum Register {
    SP,
    PC,
    FP,
    LR,
    R(usize),
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Register::SP => write!(f, "sp"),
            Register::PC => write!(f, "pc"),
            Register::FP => write!(f, "fp"),
            Register::LR => write!(f, "lr"),
            Register::R(n) => write!(f, "r{}", n),
        }
    }
}

trait ToU32 {
    fn to_u32(&self) -> u32;
}

impl ToU32 for Register {
    fn to_u32(&self) -> u32 {
        match self {
            Register::R(n) => *n as u32,
            Register::FP => 11,
            Register::SP => 13,
            Register::LR => 14,
            Register::PC => 15,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Instr {
    Align4,
    Section(String),
    Globl(String),
    Label(String),
    Space(usize, u8),
    Add(Register, Register, Register),
    Addi(Register, Register, i32),
    AddiEq(Register, Register, i32),
    Sub(Register, Register, Register),
    Subi(Register, Register, i32),
    Andi(Register, Register, i32),
    Push(Vec<Register>),
    Pop(Vec<Register>),
    Mov(Register, i32),
    Str(Register, Register, i32),
    Ldr(Register, Register, i32),
    B(String),
    Bl(String),
    Bx(Register),
    Blx(Register),
    Lea(Register, String),
    Swi(usize),
    SwiEq(usize),
    Cmpi(Register, usize),
    Long(usize),
    Addr(String, bool),
    Bytes(Vec<u8>),
}

impl Instr {
    pub fn size(&self, current: usize) -> usize {
        match self {
            Instr::Align4 => {
                let next = (current + 3) & !3;
                next - current
            }
            Instr::Section(_) => 0,
            Instr::Space(size, _fill) => *size,
            Instr::Globl(_l) => 0,
            Instr::Label(_l) => 0,
            Instr::Lea(_, _) => 12,
            Instr::Bytes(v) => v.len(),
            _ => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginEndBlock {
    BeginBlock,
    EndBlock,
    ForceLine,
}

pub trait Encodable {
    fn encode(&self, v: &mut Vec<u8>, r: &mut Vec<Relocation>, function: &str);
}

#[allow(dead_code)]
enum ArmCond {
    Unconditional,
    Equal,
    GreaterOrEqual,
}

impl ToU32 for ArmCond {
    fn to_u32(&self) -> u32 {
        match self {
            ArmCond::Unconditional => 14 << 28,
            ArmCond::Equal => 0,
            ArmCond::GreaterOrEqual => 10 << 28,
        }
    }
}

fn vec_from_u32(v: &mut Vec<u8>, data: u32) {
    v.push((data & 0xff) as u8);
    v.push(((data >> 8) & 0xff) as u8);
    v.push(((data >> 16) & 0xff) as u8);
    v.push((data >> 24) as u8);
}

enum ArmDataOp {
    Add,
    And,
    Sub,
    Mov,
    Cmp,
}

impl ToU32 for ArmDataOp {
    fn to_u32(&self) -> u32 {
        match self {
            ArmDataOp::Add => 4 << 21,
            ArmDataOp::And => 0,
            ArmDataOp::Sub => 2 << 21,
            ArmDataOp::Cmp => 10 << 21,
            ArmDataOp::Mov => 13 << 21,
        }
    }
}

enum ArmOp {
    Swi,
}

impl ToU32 for ArmOp {
    fn to_u32(&self) -> u32 {
        match self {
            ArmOp::Swi => 15 << 24,
        }
    }
}

struct Rn(Register);

impl ToU32 for Rn {
    fn to_u32(&self) -> u32 {
        self.0.to_u32() << 16
    }
}

struct Rd(Register);

impl ToU32 for Rd {
    fn to_u32(&self) -> u32 {
        self.0.to_u32() << 12
    }
}

struct Rm(u32, Register);

impl ToU32 for Rm {
    fn to_u32(&self) -> u32 {
        self.0 << 4 | self.1.to_u32()
    }
}

pub enum RelocationKind {
    Long,
    Branch,
}

pub struct Relocation {
    pub function: String,
    pub code_location: usize,
    pub reloc_target: String,
}

impl ToU32 for Vec<Register> {
    fn to_u32(&self) -> u32 {
        let mut out: u32 = 0;
        for r in self.iter() {
            out |= 1 << r.to_u32();
        }
        out
    }
}

impl Encodable for Instr {
    fn encode<'a>(&self, v: &mut Vec<u8>, r: &mut Vec<Relocation>, function: &str) {
        match self {
            Instr::Align4 => {
                while !v.len().is_multiple_of(4) {
                    v.push(0);
                }
            }
            Instr::Space(n, val) => {
                for _ in 0..*n {
                    v.push(*val)
                }
            }
            Instr::Bytes(vs) => {
                v.extend(vs.clone());
            }
            Instr::Long(l) => {
                vec_from_u32(v, *l as u32);
            }
            Instr::Addr(target, text) => {
                r.push(Relocation {
                    function: function.to_string(),
                    code_location: v.len(),
                    reloc_target: target.clone(),
                });
                let offset = if *text { 4 } else { 0 };
                vec_from_u32(v, offset);
            }
            Instr::Add(r_d, r_s, r_a) => vec_from_u32(
                v,
                ArmCond::Unconditional.to_u32()
                    | ArmDataOp::Add.to_u32()
                    | Rn(r_s.clone()).to_u32()
                    | Rd(r_d.clone()).to_u32()
                    | Rm(0, r_a.clone()).to_u32(),
            ),
            Instr::Addi(r_d, r_s, imm) => vec_from_u32(
                v,
                ArmCond::Unconditional.to_u32()
                    | ArmDataOp::Add.to_u32()
                    | Rn(r_s.clone()).to_u32()
                    | Rd(r_d.clone()).to_u32()
                    | (1 << 25)
                    | (*imm as u32),
            ),
            Instr::AddiEq(r_d, r_s, imm) => vec_from_u32(
                v,
                ArmCond::Equal.to_u32()
                    | ArmDataOp::Add.to_u32()
                    | Rn(r_s.clone()).to_u32()
                    | Rd(r_d.clone()).to_u32()
                    | (1 << 25)
                    | (*imm as u32),
            ),
            Instr::Sub(r_d, r_s, r_a) => vec_from_u32(
                v,
                ArmCond::Unconditional.to_u32()
                    | ArmDataOp::Sub.to_u32()
                    | Rn(r_s.clone()).to_u32()
                    | Rd(r_d.clone()).to_u32()
                    | Rm(0, r_a.clone()).to_u32(),
            ),
            Instr::Subi(r_d, r_s, imm) => vec_from_u32(
                v,
                ArmCond::Unconditional.to_u32()
                    | ArmDataOp::Sub.to_u32()
                    | Rn(r_s.clone()).to_u32()
                    | Rd(r_d.clone()).to_u32()
                    | (1 << 25)
                    | (*imm as u32),
            ),
            Instr::Andi(r_d, r_s, imm) => vec_from_u32(
                v,
                ArmCond::Unconditional.to_u32()
                    | ArmDataOp::And.to_u32()
                    | Rn(r_s.clone()).to_u32()
                    | Rd(r_d.clone()).to_u32()
                    | (1 << 25)
                    | (*imm as u32),
            ),
            Instr::Mov(r_d, imm) => vec_from_u32(
                v,
                ArmCond::Unconditional.to_u32()
                    | ArmDataOp::Mov.to_u32()
                    | Rd(r_d.clone()).to_u32()
                    | (1 << 25)
                    | (*imm as u32),
            ),
            Instr::Push(rs) => vec_from_u32(
                v,
                ArmCond::Unconditional.to_u32()
                    | 4 << 25
                    | Rn(Register::SP).to_u32()
                    | 1 << 21
                    | 1 << 24
                    | rs.to_u32(),
            ),
            Instr::Pop(rs) => vec_from_u32(
                v,
                ArmCond::Unconditional.to_u32()
                    | 4 << 25
                    | Rn(Register::SP).to_u32()
                    | 1 << 20
                    | 1 << 21
                    | 1 << 23
                    | rs.to_u32(),
            ),
            Instr::Str(rd, rs, off) => vec_from_u32(
                v,
                ArmCond::Unconditional.to_u32()
                    | 1 << 26
                    | 1 << 24
                    | 1 << 23
                    | Rn(rs.clone()).to_u32()
                    | Rd(rd.clone()).to_u32()
                    | (((65536 + off) & 0xff) as u32),
            ),
            Instr::Ldr(rd, rs, off) => vec_from_u32(
                v,
                ArmCond::Unconditional.to_u32()
                    | 1 << 26
                    | 1 << 24
                    | 1 << 23
                    | 1 << 20
                    | Rn(rs.clone()).to_u32()
                    | Rd(rd.clone()).to_u32()
                    | (((65536 + off) & 0xff) as u32),
            ),
            Instr::B(target) => {
                r.push(Relocation {
                    function: function.to_string(),
                    code_location: v.len(),
                    reloc_target: target.clone(),
                });
                vec_from_u32(v, ArmCond::Unconditional.to_u32() | 5 << 25);
            }
            Instr::Bl(target) => {
                r.push(Relocation {
                    function: function.to_string(),
                    code_location: v.len(),
                    reloc_target: target.clone(),
                });
                vec_from_u32(v, ArmCond::Unconditional.to_u32() | 5 << 25 | 1 << 24);
            }
            Instr::Bx(r) => {
                vec_from_u32(v, ArmCond::Unconditional.to_u32() | 0x12fff10 | r.to_u32());
            }
            Instr::Blx(r) => {
                vec_from_u32(v, ArmCond::Unconditional.to_u32() | 0x12fff30 | r.to_u32());
            }
            Instr::Lea(rd, target) => {
                // Emit a load from +8 (0 as encoded).
                vec_from_u32(
                    v,
                    ArmCond::Unconditional.to_u32()
                        | 1 << 26
                        | 1 << 24
                        | 1 << 23
                        | 1 << 20
                        | Rn(Register::PC).to_u32()
                        | Rd(rd.clone()).to_u32(),
                );
                // Emit a jump to +8
                vec_from_u32(v, ArmCond::Unconditional.to_u32() | 5 << 25);
                r.push(Relocation {
                    function: function.to_string(),
                    code_location: v.len(),
                    reloc_target: target.clone(),
                });
                // Relocatable space.
                vec_from_u32(v, 4);
            }
            Instr::Swi(n) => {
                vec_from_u32(
                    v,
                    ArmCond::Unconditional.to_u32() | ArmOp::Swi.to_u32() | (*n as u32),
                );
            }
            Instr::SwiEq(n) => {
                vec_from_u32(
                    v,
                    ArmCond::Equal.to_u32() | ArmOp::Swi.to_u32() | (*n as u32),
                );
            }
            Instr::Cmpi(r, n) => {
                vec_from_u32(
                    v,
                    ArmCond::Unconditional.to_u32()
                        | ArmDataOp::Cmp.to_u32()
                        | 1 << 25
                        | 1 << 20
                        | Rn(r.clone()).to_u32()
                        | (*n as u32),
                );
            }
            _ => {}
        }
    }
}

#[test]
fn test_arm_encoding_add_1_3_7() {
    let mut v = Vec::new();
    let mut r = Vec::new();
    Instr::Add(Register::R(1), Register::R(3), Register::R(7)).encode(&mut v, &mut r, "test");
    assert_eq!(b"\x07\x10\x83\xe0".to_vec(), v);
}

#[test]
fn test_arm_encoding_swi() {
    let mut v = Vec::new();
    let mut r = Vec::new();
    Instr::Swi(13).encode(&mut v, &mut r, "test");
    assert_eq!(b"\x0d\x00\x00\xef".to_vec(), v);
}

impl fmt::Display for Instr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Instr::Align4 => write!(f, "  .align 4"),
            Instr::Section(s) => write!(f, "  .section {s}"),
            Instr::Space(size, fill) => write!(f, "  .space {size},{fill}"),
            Instr::Globl(l) => write!(f, "  .globl {l}"),
            Instr::Label(l) => write!(f, "{l}:"),
            Instr::Add(r_d, r_s, r_a) => write!(f, "  add {r_d}, {r_s}, {r_a}"),
            Instr::Addi(r_d, r_s, imm) => write!(f, "  add {r_d}, {r_s}, #{imm}"),
            Instr::AddiEq(r_d, r_s, imm) => write!(f, "  addeq {r_d}, {r_s}, #{imm}"),
            Instr::Andi(r_d, r_s, imm) => write!(f, "  and {r_d}, {r_s}, #{imm}"),
            Instr::Sub(r_d, r_s, r_a) => write!(f, "  sub {r_d}, {r_s}, {r_a}"),
            Instr::Subi(r_d, r_s, imm) => write!(f, "  sub {r_d}, {r_s}, #{imm}"),
            Instr::Cmpi(r, imm) => write!(f, "  cmp {r}, #{imm}"),
            Instr::Push(rs) => {
                write!(f, "  push {{")?;
                let mut sep = "";
                for r in rs.iter() {
                    write!(f, "{sep}{r}")?;
                    sep = ", ";
                }
                write!(f, "}}")
            }
            Instr::Pop(rs) => {
                write!(f, "  pop {{")?;
                let mut sep = "";
                for r in rs.iter() {
                    write!(f, "{sep}{r}")?;
                    sep = ", ";
                }
                write!(f, "}}")
            }
            Instr::Mov(r_d, imm) => write!(f, "  mov {r_d}, #{imm}"),
            Instr::Str(r_s, r_a, imm) => write!(f, "  str {r_s}, [{r_a}, #{imm}]"),
            Instr::Ldr(r_d, r_a, imm) => write!(f, "  ldr {r_d}, [{r_a}, #{imm}]"),
            Instr::B(l) => write!(f, "  b {l}"),
            Instr::Bl(l) => write!(f, "  bl {l}"),
            Instr::Bx(r) => write!(f, "  bx {r}"),
            Instr::Blx(r) => write!(f, "  blx {r}"),
            Instr::Lea(r, l) => write!(f, "  ldr {r}, ={l}"),
            Instr::Swi(n) => write!(f, "  swi {n}"),
            Instr::SwiEq(n) => write!(f, "  swieq {n}"),
            Instr::Long(n) => write!(f, "  .long {n}"),
            Instr::Addr(lbl, _) => write!(f, "  .long {lbl}"),
            Instr::Bytes(v) => {
                let mut sep = " ";
                write!(f, "  .byte")?;
                for b in v.iter() {
                    write!(f, "{sep}{b}")?;
                    sep = ", ";
                }
                Ok(())
            }
        }
    }
}
