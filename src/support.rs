use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::rc::Rc;
use sha2::{Sha256, Digest};
use crate::sexp::{SExp, SExpValue, CreateSExp};

pub fn debug_sha256tree<T: SExp>(sexp: T) -> Vec<u8> {
    match sexp.explode() {
        SExpValue::Cons(_, left, right) => {
            let hash_left = debug_sha256tree(left);
            let hash_right = debug_sha256tree(right);
            let mut hasher = Sha256::new();
            hasher.update([2]);
            hasher.update(hash_left);
            hasher.update(hash_right);
            hasher.finalize().to_vec()
        }
        _ => {
            let (_, bytes) = sexp
                .atom_bytes::<T>()
                .expect("non-cons debug sexp should atomize");
            let mut hasher = Sha256::new();
            hasher.update([1]);
            hasher.update(bytes);
            hasher.finalize().to_vec()
        }
    }
}

pub fn debug_truthy<T: SExp>(sexp: T) -> bool {
    !sexp.nilp()
}

pub fn debug_is_atom<T: SExp>(sexp: T) -> Option<(T::Srcloc, Vec<u8>)> {
    sexp.atom_bytes::<T>()
}

pub fn debug_is_wrapped_atom<T: SExp>(sexp: T) -> Option<(T::Srcloc, Vec<u8>)> {
    match sexp.explode() {
        SExpValue::Cons(_, left, right) => {
            let (loc, atom) = match left.explode() {
                SExpValue::Atom(loc, atom) => (loc, atom),
                _ => return None,
            };
            if debug_truthy(right) {
                None
            } else {
                Some((loc, atom))
            }
        }
        _ => None,
    }
}

fn debug_collect_by_hash<T: SExp>(hash: &[u8], sexp: T, matches: &mut Vec<T>) -> Vec<u8> {
    if let SExpValue::Cons(_, left, right) = sexp.explode() {
        let hash_left = debug_collect_by_hash(hash, left, matches);
        let hash_right = debug_collect_by_hash(hash, right, matches);
        let mut hasher = Sha256::new();
        hasher.update([2]);
        hasher.update(hash_left);
        hasher.update(hash_right);
        let my_hash = hasher.finalize().to_vec();
        if my_hash == hash {
            matches.push(sexp);
        }
        my_hash
    } else {
        let the_hash = debug_sha256tree(sexp.clone());
        if the_hash == hash {
            matches.push(sexp);
        }
        the_hash
    }
}

pub fn debug_find_all_by_hash<T: SExp>(hash: &[u8], sexp: T) -> Vec<T> {
    let mut matches = Vec::new();
    debug_collect_by_hash(hash, sexp, &mut matches);
    matches
}
