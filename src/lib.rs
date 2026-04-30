pub mod code;
pub mod loader;
pub mod sexp;
pub mod support;

use num_bigint::{BigInt, ToBigInt};

pub type Number = BigInt;

fn bi_zero() -> BigInt {
    BigInt::default()
}

fn bi_one() -> BigInt {
    1_u32.to_bigint().unwrap()
}

pub fn write_u32(content: &mut [u8], offset: usize, value: u32) {
    content[offset] = (value & 0xff) as u8;
    content[offset + 1] = ((value >> 8) & 0xff) as u8;
    content[offset + 2] = ((value >> 16) & 0xff) as u8;
    content[offset + 3] = ((value >> 24) & 0xff) as u8;
}
