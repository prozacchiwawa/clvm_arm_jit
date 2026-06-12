use std::borrow::Borrow;
use std::collections::HashMap;
use std::rc::Rc;

use chialisp::compiler::debug::build_swap_table_mut;
use chialisp::compiler::sexp;

fn relabel_inner_(
    code_map: &HashMap<String, sexp::SExp>,
    swap_table: &HashMap<sexp::SExp, String>,
    code: &sexp::SExp,
) -> sexp::SExp {
    swap_table
        .get(code)
        .map(|res| {
            let new_obj = code_map.get(res).cloned().unwrap_or_else(|| code.clone());
            match &new_obj {
                sexp::SExp::Cons(_, a, b) => {
                    let new_a = relabel_inner_(code_map, swap_table, a.borrow());
                    let new_b = relabel_inner_(code_map, swap_table, b.borrow());
                    sexp::SExp::Cons(new_obj.loc(), Rc::new(new_a), Rc::new(new_b))
                }
                _ => new_obj.clone(),
            }
        })
        .unwrap_or_else(|| match code {
            sexp::SExp::Cons(_, a, b) => {
                let new_a = relabel_inner_(code_map, swap_table, a.borrow());
                let new_b = relabel_inner_(code_map, swap_table, b.borrow());
                sexp::SExp::Cons(code.loc(), Rc::new(new_a), Rc::new(new_b))
            }
            _ => code.clone(),
        })
}

pub fn relabel(code_map: &HashMap<String, sexp::SExp>, code: &sexp::SExp) -> sexp::SExp {
    let mut inv_swap_table = HashMap::new();
    build_swap_table_mut(&mut inv_swap_table, code);
    let mut swap_table = HashMap::new();
    for ent in inv_swap_table.iter() {
        swap_table.insert(ent.1.clone(), ent.0.clone());
    }
    relabel_inner_(code_map, &swap_table, code)
}
