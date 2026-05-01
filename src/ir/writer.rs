use std::borrow::Borrow;
use std::rc::Rc;
use num_bigint::ToBigInt;

use crate::ir::repr::IRRepr;
use crate::sexp::{Number, bi_one, bi_zero};

#[derive(Debug)]
enum IROutputState {
    Start(Rc<IRRepr>),
    MaybeSep(Rc<IRRepr>),
    ListOf(Rc<IRRepr>),
    DotThen(Rc<IRRepr>),
    EndParen,
}

#[derive(Debug)]
pub struct IROutputIterator {
    state: Vec<IROutputState>,
}

impl IROutputIterator {
    pub fn new(ir_sexp: Rc<IRRepr>) -> IROutputIterator {
        IROutputIterator {
            state: vec![IROutputState::Start(ir_sexp)],
        }
    }
}

pub struct TConvertOption {
    pub signed: bool,
}

/**
 * Get python's bytes.__repr__ style string.
 * @see https://github.com/python/cpython/blob/main/Objects/bytesobject.c#L1337
 * @param {Uint8Array} r - byteArray to stringify
 */
pub fn pybytes_repr(r: &[u8], dquoted: bool, full_repr: bool) -> String {
    let mut squotes = 0;
    let mut dquotes = 0;
    for b in r.iter() {
        let c = *b as char;
        match c {
            '\'' => squotes += 1,
            '\"' => dquotes += 1,
            _ => (),
        }
    }
    let mut quote = b'\'';
    if squotes > 0 && dquotes == 0 || dquoted {
        quote = b'\"';
    }

    let mut s = Vec::new();

    if !dquoted {
        s.push(b'b');
    }

    s.push(quote);

    for b in r.iter() {
        if *b == quote || (*b == b'\\' && full_repr) {
            s.push(b'\\');
            s.push(*b);
        } else if *b == b'\t' {
            s.push(b'\\');
            s.push(b't');
        } else if *b == b'\n' {
            s.push(b'\\');
            s.push(b'n');
        } else if *b == b'\r' {
            s.push(b'\\');
            s.push(b'r');
        } else if *b < b' ' || *b >= 0x7f {
            s.push(b'\\');
            s.push(b'x');
            for by in hex::encode(vec![*b]).bytes() {
                s.push(by);
            }
        } else {
            s.push(*b);
        }
    }

    s.push(quote);

    String::from_utf8_lossy(&s).to_string()
}

pub fn get_u32(v: &[u8], n: usize) -> u32 {
    let p1 = v[n] as u32;
    let p2 = v[n + 1] as u32;
    let p3 = v[n + 2] as u32;
    let p4 = v[n + 3] as u32;
    p1 | (p2 << 8) | (p3 << 16) | (p4 << 24)
}

pub fn bigint_from_bytes(b: &[u8], option: Option<TConvertOption>) -> Number {
    if b.len() == 0 {
        return bi_zero();
    }

    let signed = option.map(|cvt| cvt.signed).unwrap_or_else(|| false);
    let mut unsigned = bi_zero();

    let bytes4_remain = b.len() % 4;
    let bytes4_length = (b.len() - bytes4_remain) / 4;

    let mut order = bi_one();

    if bytes4_length > 0 {
        for i_reverse in 0..bytes4_length {
            let i = bytes4_length - i_reverse - 1;
            let byte32 = get_u32(&b, i * 4 + bytes4_remain);
            unsigned += byte32.to_bigint().unwrap() * order.clone();
            order <<= 32;
        }
    }

    if bytes4_remain > 0 {
        if bytes4_length == 0 {
            order = bi_one();
        }
        for i_reverse in 0..bytes4_remain {
            let i = bytes4_remain - i_reverse - 1;
            let byte = b[i];
            unsigned += byte.to_bigint().unwrap() * order.clone();
            order <<= 8;
        }
    }

    // If the first bit is 1, it is recognized as a negative number.
    if signed && ((b[0] & 0x80) != 0) {
        return unsigned - (bi_one() << (b.len() * 8));
    }
    unsigned
}

fn output_with_radix(bits: usize, bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::default();
    let raw_content_bits = 8 * bytes.len();
    let digit_mask = (1 << bits) - 1;
    let digits = (raw_content_bits + bits) / bits;
    let digit_bits = bits * digits;
    let mut buffer_bit = digit_bits % 8;
    let mut buffer: u32 = 0;

    if bytes.is_empty() {
        result.push(b'0');
        return result;
    }

    // If the leftmost byte is zero, then we must include a binary or octal digit
    // to indicate that it should be padded.
    let mut need_padding = bytes[0] == 0;

    if need_padding && bytes.len() == 1 {
        result.push(b'0');
        result.push(b'0');
        return result;
    }

    let mut produce_output = false;

    for byte in bytes.iter() {
        buffer = (buffer << 8) | *byte as u32;
        buffer_bit += 8;
        while buffer_bit >= bits {
            buffer_bit -= bits;
            let digit_value = (buffer >> buffer_bit) & digit_mask;
            if digit_value != 0 || need_padding && !produce_output && buffer_bit < bits {
                produce_output = true;
                need_padding = false;
            }
            if produce_output {
                result.push(b'0' + (digit_value as u8));
            }
        }
        // Regardless of anything else, start producing output on the second
        // byte.
        produce_output = true;
    }

    result
}

impl Iterator for IROutputIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.state.pop() {
                None => {
                    return None;
                }
                Some(IROutputState::EndParen) => {
                    return Some(")".to_string());
                }
                Some(IROutputState::Start(v)) => match v.borrow() {
                    IRRepr::Cons(l, r) => {
                        self.state.push(IROutputState::ListOf(Rc::new(IRRepr::Cons(
                            l.clone(),
                            r.clone(),
                        ))));
                        return Some("(".to_string());
                    }
                    IRRepr::Null => {
                        return Some("()".to_string());
                    }
                    IRRepr::Quotes(q) => {
                        return Some(pybytes_repr(q, false, true));
                    }
                    IRRepr::Int(i, signed) => {
                        let opts = TConvertOption { signed: *signed };
                        return Some(bigint_from_bytes(i, Some(opts)).to_string());
                    }
                    IRRepr::Hex(h) => {
                        return Some(format!("0x{}", hex::encode(&h)));
                    }
                    IRRepr::Octal(o) => {
                        return Some(format!("0x{}", hex::encode(&o)));
                    }
                    IRRepr::Binary(b) => {
                        return Some(format!("0x{}", hex::encode(&b)));
                    }
                    IRRepr::Symbol(s) => {
                        return Some(s.to_string());
                    }
                },
                Some(IROutputState::MaybeSep(sub)) => match sub.borrow() {
                    IRRepr::Null => {
                        self.state.push(IROutputState::EndParen);
                    }
                    _ => {
                        self.state.push(IROutputState::ListOf(sub.clone()));
                        return Some(" ".to_string());
                    }
                },
                Some(IROutputState::ListOf(v)) => match v.borrow() {
                    IRRepr::Cons(l, r) => {
                        self.state.push(IROutputState::MaybeSep(r.clone()));
                        self.state.push(IROutputState::Start(l.clone()));
                    }
                    IRRepr::Null => {
                        self.state.push(IROutputState::EndParen);
                    }
                    _ => {
                        self.state.push(IROutputState::EndParen);
                        self.state.push(IROutputState::DotThen(v.clone()));
                        return Some(". ".to_string());
                    }
                },
                Some(IROutputState::DotThen(v)) => match v.borrow() {
                    IRRepr::Cons(l, r) => {
                        self.state.push(IROutputState::ListOf(r.clone()));
                        self.state.push(IROutputState::Start(l.clone()));
                    }
                    _ => {
                        self.state.push(IROutputState::Start(v.clone()));
                    }
                },
            }
        }
    }
}
