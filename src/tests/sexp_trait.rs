use std::rc::Rc;

use chialisp::classic::clvm::casts::bigint_to_bytes_clvm;
use chialisp::compiler::clvm::sha256tree;
use chialisp::compiler::sexp::{SExp, parse_sexp};
use chialisp::compiler::srcloc::Srcloc;
use chialisp::util::Number;

use crate::sexp;
use crate::sexp::{SExpValue, Until, bi_zero};

impl sexp::SExp for Rc<SExp> {
    fn sha256tree(&self) -> Vec<u8> {
        sha256tree(self.clone())
    }

    fn to_number(&self) -> Option<Number> {
        self.as_ref().get_number().ok()
    }

    fn proper_list(&self) -> Option<Vec<Self>> {
        let mut res = Vec::new();
        let mut track = self.clone();

        loop {
            if track.nilp() {
                return Some(res);
            }

            match track.explode() {
                SExpValue::Cons(left, right) => {
                    res.push(left);
                    track = right;
                }
                _ => return None,
            }
        }
    }

    fn explode(&self) -> SExpValue<Self> {
        match self.as_ref() {
            SExp::Nil(_loc) => SExpValue::Nil,
            SExp::Cons(_loc, left, right) => SExpValue::Cons(left.clone(), right.clone()),
            SExp::Integer(_loc, i) => {
                if *i == bi_zero() {
                    return SExpValue::Nil;
                }
                SExpValue::Atom(bigint_to_bytes_clvm(i).data().clone())
            }
            SExp::QuotedString(_loc, _, bytes) | SExp::Atom(_loc, bytes) => {
                SExpValue::Atom(bytes.clone())
            }
        }
    }
}

impl sexp::Srcloc for Srcloc {
    fn start(filename: &str) -> Self {
        Srcloc::start(filename)
    }
    fn filename(&self) -> String {
        self.file.to_string()
    }
    fn line(&self) -> usize {
        self.line
    }
    fn col(&self) -> usize {
        self.col
    }
    fn overlap(&self, other: &Self) -> bool {
        self.overlap(other)
    }
    fn until(&self) -> Option<Until> {
        if let Some(u) = &self.until {
            return Some(Until {
                line: u.line as u32,
                col: u.col as u32,
            });
        }

        None
    }
}

impl sexp::HasSrcloc for Rc<SExp> {
    type Srcloc = Srcloc;

    fn loc(&self) -> Srcloc {
        self.as_ref().loc()
    }
}

pub struct CreateChialispSExp;

impl sexp::CreateSExp<Rc<SExp>> for CreateChialispSExp {
    fn atom(loc: Srcloc, bytes: &[u8]) -> Rc<SExp> {
        Rc::new(SExp::Atom(loc, bytes.to_vec()))
    }

    fn cons(loc: Srcloc, a: Rc<SExp>, b: Rc<SExp>) -> Rc<SExp> {
        Rc::new(SExp::Cons(loc, a, b))
    }

    fn parse_sexp<I>(start: Srcloc, input: I) -> Result<Vec<Rc<SExp>>, (Srcloc, String)>
    where
        I: Iterator<Item = u8>,
    {
        parse_sexp(start, input)
    }
}
