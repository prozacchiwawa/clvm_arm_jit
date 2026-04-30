use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::rc::Rc;

use num_bigint::{BigInt, ToBigInt};
use sha2::{Sha256, Digest};

pub fn u8_from_number(v: Number) -> Vec<u8> {
    v.to_signed_bytes_be()
}

pub type Number = BigInt;

pub fn bi_zero() -> BigInt {
    BigInt::default()
}

pub fn bi_one() -> BigInt {
    1_u32.to_bigint().unwrap()
}

// Traits for varying the type of CLVM expressions.
#[derive(Clone, Debug)]
pub enum SExpValue<T: SExp> {
    Nil(T::Srcloc),
    Atom(T::Srcloc, Vec<u8>),
    Cons(T::Srcloc, T, T),
}

pub trait SExp: Clone + Display {
    type Srcloc: Srcloc;
    fn loc(&self) -> Self::Srcloc;
    fn atomize(&self) -> Self;
    fn to_number(&self) -> Option<Number>;
    fn proper_list(&self) -> Option<Vec<Self>>;
    fn explode(&self) -> SExpValue<Self>;

    fn nilp(&self) -> bool {
        matches!(self.atom_bytes::<Self>(), Some((_, bytes)) if bytes.is_empty())
    }

    fn atom_bytes<T: SExp>(&self) -> Option<(Self::Srcloc, Vec<u8>)> {
        match self.explode() {
            SExpValue::Cons(_, _, _) => None,
            SExpValue::Nil(loc) => Some((loc, Vec::new())),
            SExpValue::Atom(loc, bytes) => Some((loc, bytes)),
        }
    }
}

pub struct Until {
    pub line: u32,
    pub col: u32,
}

pub trait Srcloc: Clone + Debug + Display {
    fn start(filename: &str) -> Self;
    fn filename(&self) -> String;
    fn line(&self) -> usize;
    fn col(&self) -> usize;
    fn overlap(&self, other: &Self) -> bool;
    fn until(&self) -> Option<Until>;
}

pub trait CreateSExp {
    fn atom<S: SExp>(loc: S::Srcloc, bytes: &[u8]) -> S;
    fn cons<S: SExp>(loc: S::Srcloc, a: S, b: S) -> S;

    fn parse_sexp<S: SExp, I>(start: S::Srcloc, input: I) -> Result<Vec<S>, (S::Srcloc, String)>
    where
        I: Iterator<Item = u8>;
}

pub fn dequote<T: SExp>(sexp: T) -> Option<T> {
    match sexp.explode() {
        SExpValue::Cons(_, left, right) => match left.explode() {
            SExpValue::Atom(_, atom) if atom == b"\x01" => Some(right),
            _ => None,
        },
        _ => None,
    }
}
