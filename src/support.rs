use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::rc::Rc;
use sha2::{Sha256, Digest};

use crate::Number;

pub fn u8_from_number(v: Number) -> Vec<u8> {
    v.to_signed_bytes_be()
}

/// Given an SExp and a transformation, make a map of the transformed subtrees of
/// the given SExp in code that's indexed by treehash.  This will merge equivalent
/// subtrees but the uses to which it's put will generally work well enough.
///
/// Given how it's used downstream, there'd be no way to disambiguate anyhow.
///
/// A fuller explanation:e
///
/// This is purely syntactic so there's no environment in play here, basically
/// just about the CLVM value space and how program source code is represented in
/// CLVM values.
///
/// These are all equivalent in CLVM:
///
/// ##    "Y" Y 89 0x59
///
/// So a user writing:
///
/// ##    (list Y "Y" 89 0x59) ;; 1
///
/// Gives the compiler back a CLVM expression that could mean any of these
/// things:
///
/// ##    (c Y (c Y (c Y (c Y ()))))
/// ##    (c "Y" (c "Y" (c "Y" (c "Y" ()))))
/// ##    (c 89 (c 89 (c 89 (c 89 ()))))
/// ##    (c 0x59 (c 0x59 (c 0x59 (c 0x59 ()))))
///
/// So the compiler rehydrates this result by taking the largest matching subtrees
/// from the user's input and replacing it. The above is a pathological case for
/// this, and in general, doing something like:
///
/// ##    (if
/// ##      (some-condition X)
/// ##      (do-something-a X)
/// ##      (let ((Y (something X))) (do-something-else Y))
/// ##      )
///
/// Expands into a macro invocation for if, and comes back with 3 subtrees
/// identical to the user's input, so those whole trees return with their source
/// locations and the form of the user's input (Ys not rewritten as the number 89,
/// but as identifiers).
pub fn build_table_mut<T: DebugSExp+Eq+Hash, X, C: DebugCreateAtom>(
    code_map: &mut HashMap<String, X>,
    tx: &dyn Fn(&T) -> X,
    code: &T,
) -> Vec<u8> {
    match code.explode() {
        DebugSExpValue::<T>::Cons(_l, a, b) => {
            let mut left = build_table_mut::<T, X, C>(code_map, tx, a.borrow());
            let mut right = build_table_mut::<T, X, C>(code_map, tx, b.borrow());
            let mut data = vec![2];
            data.append(&mut left);
            data.append(&mut right);
            let treehash = Sha256::digest(&data);
            code_map.entry(hex::encode(&treehash)).or_insert_with(|| tx(code));
            treehash.to_vec()
        }
        DebugSExpValue::<T>::Atom(_, a) => {
            let mut data = vec![1];
            data.append(&mut a.clone());
            let treehash = Sha256::digest(&data);
            code_map.insert(hex::encode(&treehash), tx(code));
            treehash.to_vec()
        }
        DebugSExpValue::<T>::Nil(l) => build_table_mut::<T, X, C>(code_map, tx, &C::atom::<T>(l.clone(), &[]))
    }
}

pub fn build_symbol_table_mut<T: DebugSExp+Eq+Hash, C: DebugCreateAtom>(code_map: &mut HashMap<String, String>, code: &T) -> Vec<u8> {
    build_table_mut::<T, String, C>(code_map, &|sexp: &T| sexp.loc().to_string(), code)
}

pub fn build_swap_table_mut<T: DebugSExp+Eq+Hash, C: DebugCreateAtom>(code_map: &mut HashMap<String, T>, code: &T) -> Vec<u8> {
    build_table_mut::<T, T, C>(code_map, &|sexp: &T| sexp.clone(), code)
}

fn relabel_inner_<S: DebugSExp+Eq+Hash, C: DebugCreateAtom>(
    code_map: &HashMap<String, S>,
    swap_table: &HashMap<S, String>,
    code: &S,
) -> S {
    swap_table
        .get(code)
        .and_then(|res| code_map.get(res))
        .cloned()
        .unwrap_or_else(|| match code.explode() {
            DebugSExpValue::<S>::Cons(l, a, b) => {
                let new_a = relabel_inner_::<S, C>(code_map, swap_table, a.borrow());
                let new_b = relabel_inner_::<S, C>(code_map, swap_table, b.borrow());
                C::cons::<S>(l.clone(), new_a, new_b)
            }
            _ => code.clone(),
        })
}

/// Given a map generated from preexisting code, replace value identical subtrees
/// with their rich valued equivalents.
///
/// Consider code that has run through a macro:
///
/// (defmacro M (VAR) VAR)
///
/// vs
///
/// (defmacro M (VAR) (q . 87))
///
/// As originally envisioned, chialisp macros compile to CLVM programs and consume
/// the program as CLVM code.  When the language is maximally permissive this isn't
/// inconsistent; a "W" string is the same representation as a W atom (an
/// identifier) and the number 87.  The problem is when users want the language to
/// distinguish between legal and illegal uses of identifiers, this poses a
/// problem.
///
/// In the above code, the macro produces a CLVM value.  That value has a valid
/// interpretation as the number 87, the string constant "W" or the identifier W.
/// If I make the rule that 'identifiers must be bound' under these conditions
/// then I've also made the rule that "one cannot return a number from a macro that
/// doesn't correspond coincidentally to the name of a bound variable, which
/// likely isn't expected given that the chialisp language gives the user the
/// ability to input this value in the distinct forms of integer, identifier,
/// string and such.  Therefore, the 87 here and the W in the next paragraph refer
/// to the same ambigious value in the CLVM value space.  A fix for this has been
/// held off for a while while a good long term solution was thought through, which
/// will appear in the form of macros that execute in the value space of chialisp
/// SExp (with distinctions between string, integer, identifier etc) and that
/// improvement is in process.
///
/// The raw result of either the integer 87, which doesn't give much clue as
/// to what's intended.  In one case, it *might* be true that VAR was untransformed
/// and the user intends the compiler to check whether downstream uses of W are
/// bound, in the second case, it's clear that won't be intended.
///
/// In classic chialisp, unclaimed identifiers are always treated as constant
/// numbers, but when we're being asked to make things strict, deciding which
/// to do makes things difficult.  Existing macro code assumes it can use unbound
/// words to name functions in the parent frame, among other things and they'll
/// be passed through as atom constants if not bound.
///
/// Relabel here takes a map made from the input of the macro invocation and
/// substitutes any equivalent subtree from before the application, which will
/// retain the form the user gave it.  This is fragile but works for now.
///
/// A way to do this better is planned.
pub fn relabel<S: DebugSExp+Eq+Hash, C: DebugCreateAtom>(code_map: &HashMap<String, S>, code: &S) -> S {
    let mut inv_swap_table = HashMap::new();
    build_swap_table_mut::<S, C>(&mut inv_swap_table, code);
    let mut swap_table = HashMap::new();
    for ent in inv_swap_table.iter() {
        swap_table.insert(ent.1.clone(), ent.0.clone());
    }
    relabel_inner_::<S, C>(code_map, &swap_table, code)
}

// Traits for varying the type of CLVM expressions.
#[derive(Clone, Debug)]
pub enum DebugSExpValue<T: DebugSExp> {
    Nil(T::Srcloc),
    Atom(T::Srcloc, Vec<u8>),
    Cons(T::Srcloc, T, T),
}

pub struct Until {
    pub line: u32,
    pub col: u32,
}

pub trait DebugSrcloc: Clone + Debug + Display {
    fn start(filename: &str) -> Self;
    fn filename(&self) -> String;
    fn line(&self) -> usize;
    fn col(&self) -> usize;
    fn overlap(&self, other: &Self) -> bool;
    fn until(&self) -> Option<Until>;
}

pub trait DebugCreateAtom {
    fn atom<SExp: DebugSExp>(loc: SExp::Srcloc, bytes: &[u8]) -> SExp;
    fn cons<SExp: DebugSExp>(loc: SExp::Srcloc, a: SExp, b: SExp) -> SExp;

    fn parse_sexp<SExp: DebugSExp, I>(start: SExp::Srcloc, input: I) -> Result<Vec<SExp>, (SExp::Srcloc, String)>
    where
        I: Iterator<Item = u8>;
}

pub trait DebugSExp: Clone + Display {
    type Srcloc: DebugSrcloc;
    fn loc(&self) -> Self::Srcloc;
    fn atomize(&self) -> Self;
    fn to_number(&self) -> Option<Number>;
    fn proper_list(&self) -> Option<Vec<Self>>;
    fn explode(&self) -> DebugSExpValue<Self>;

    fn nilp(&self) -> bool {
        matches!(self.atom_bytes::<Self>(), Some((_, bytes)) if bytes.is_empty())
    }

    fn atom_bytes<T: DebugSExp>(&self) -> Option<(Self::Srcloc, Vec<u8>)> {
        match self.explode() {
            DebugSExpValue::Cons(_, _, _) => None,
            DebugSExpValue::Nil(loc) => Some((loc, Vec::new())),
            DebugSExpValue::Atom(loc, bytes) => Some((loc, bytes)),
        }
    }
}

pub fn debug_sha256tree<T: DebugSExp>(sexp: T) -> Vec<u8> {
    match sexp.explode() {
        DebugSExpValue::Cons(_, left, right) => {
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

pub fn debug_truthy<T: DebugSExp>(sexp: T) -> bool {
    !sexp.nilp()
}

pub fn debug_is_atom<T: DebugSExp>(sexp: T) -> Option<(T::Srcloc, Vec<u8>)> {
    sexp.atom_bytes::<T>()
}

pub fn debug_is_wrapped_atom<T: DebugSExp>(sexp: T) -> Option<(T::Srcloc, Vec<u8>)> {
    match sexp.explode() {
        DebugSExpValue::Cons(_, left, right) => {
            let (loc, atom) = match left.explode() {
                DebugSExpValue::Atom(loc, atom) => (loc, atom),
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

pub fn debug_dequote<T: DebugSExp>(sexp: T) -> Option<T> {
    match sexp.explode() {
        DebugSExpValue::Cons(_, left, right) => match left.explode() {
            DebugSExpValue::Atom(_, atom) if atom == b"\x01" => Some(right),
            _ => None,
        },
        _ => None,
    }
}

fn debug_collect_by_hash<T: DebugSExp>(hash: &[u8], sexp: T, matches: &mut Vec<T>) -> Vec<u8> {
    if let DebugSExpValue::Cons(_, left, right) = sexp.explode() {
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

pub fn debug_find_all_by_hash<T: DebugSExp>(hash: &[u8], sexp: T) -> Vec<T> {
    let mut matches = Vec::new();
    debug_collect_by_hash(hash, sexp, &mut matches);
    matches
}
