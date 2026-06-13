use std::collections::HashMap;
use std::rc::Rc;

use clvm_to_arm_generate::code::{ElfObject, Program};
use clvmr::Allocator;

use chialisp::classic::clvm_tools::comp_input::RunAndCompileInputData;
use chialisp::classic::clvm_tools::ir::r#type::NEW_BIT_CONSTANTS;
use chialisp::classic::clvm_tools::stages;
use chialisp::classic::clvm_tools::stages::stage_0::{DefaultProgramRunner, TRunProgram};
use chialisp::classic::clvm_tools::stages::stage_2::operators::run_program_for_search_paths;
use chialisp::classic::platform::argparse::ArgumentValue;
use chialisp::compiler::clvm::convert_from_clvm_rs;
use chialisp::compiler::compiler::{DefaultCompilerOpts, compile_file};
use chialisp::compiler::comptypes::CompilerOpts;
use chialisp::compiler::debug::{build_swap_table_mut, build_symbol_table_mut};
use chialisp::compiler::sexp;
use chialisp::compiler::sexp::{decode_string, parse_sexp};
use chialisp::compiler::srcloc::Srcloc;

use crate::relabel::relabel;
use crate::sexp_trait::{CreateChialispSExp, RcSExp, SrclocWrap};

pub mod relabel;
pub mod sexp_trait;

#[cfg(test)]
pub mod tests;

pub struct CompileResult {
    pub object: ElfObject,
    pub symbols: Rc<HashMap<String, String>>,
}

pub fn match_defun(clvm: &sexp::SExp) -> Option<(Vec<u8>, SrclocWrap)> {
    if let Some(pl) = clvm.proper_list() {
        if pl.len() < 4 {
            return None;
        }

        if let sexp::SExp::Atom(_, defun) = &pl[0].atomize() {
            if defun != b"defun" {
                return None;
            }
        } else {
            return None;
        }

        if let sexp::SExp::Atom(_, name) = &pl[1].atomize() {
            return Some((name.clone(), SrclocWrap(clvm.loc())));
        }
    }

    None
}

pub fn compile(
    allocator: &mut Allocator,
    filename: &str,
    program: &str,
    output: &str,
    search_paths: &[String],
) -> Result<CompileResult, String> {
    let srcloc = Srcloc::start(filename);
    let mut symbol_table = HashMap::new();
    let runner: Rc<dyn TRunProgram> = Rc::new(DefaultProgramRunner::new());
    let mut parse_input = HashMap::new();
    parse_input.insert(
        "path_or_code".to_string(),
        ArgumentValue::ArgString(Some(filename.to_string()), program.to_string()),
    );
    let compile_input = RunAndCompileInputData::new(allocator, &parse_input)?;

    let opts = Rc::new(DefaultCompilerOpts::new(filename))
        .set_dialect(compile_input.dialect.clone())
        .set_optimize(true)
        .set_search_paths(search_paths)
        .set_frontend_opt(false);
    let parsed_program = parse_sexp(srcloc.clone(), program.bytes())
        .map_err(|e| format!("failed to parse chialisp program {filename}: {e:?}"))?;

    let mut range_results: HashMap<String, SrclocWrap> = HashMap::new();

    for element in parsed_program.iter() {
        if let Some((name, loc)) = match_defun(&element) {
            range_results.insert(decode_string(&name), loc);
        }
        if let Some(lst) = element.proper_list() {
            for lv2 in lst.iter() {
                if let Some((name, loc)) = match_defun(&lv2) {
                    range_results.insert(decode_string(&name), loc);
                }
            }
        }
    }

    let compiled = if compile_input.dialect.stepping.is_some() {
        let compiled = compile_file(allocator, runner, opts.clone(), program, &mut symbol_table)
            .map_err(|e| format!("{e:?}"))?
            .to_sexp();
        build_symbol_table_mut(&mut symbol_table, &compiled);
        compiled.into()
    } else {
        let run_script = stages::run(allocator);
        let special_runner = run_program_for_search_paths(
            &compile_input.use_filename(),
            &compile_input.search_paths,
            true,
            if compile_input.dialect.extra_numeric_constants {
                NEW_BIT_CONSTANTS
            } else {
                0
            },
        );
        let dpr = special_runner.clone();
        let input_sexp = allocator
            .new_pair(compile_input.program.parsed, compile_input.args.parsed)
            .map_err(|e| format!("failed to compose compile input: {e:?}"))?;
        let compiled = special_runner
            .run_program(allocator, run_script, input_sexp, None)
            .map(|pr| pr.1)
            .map_err(|e| format!("failed to compile {filename}: {e:?}"))?;
        symbol_table = dpr.get_compiles();

        let compiled_rc: Rc<sexp::SExp> =
            convert_from_clvm_rs(allocator, Srcloc::start(filename), compiled)
                .map_err(|e| format!("error converting clvm data: {e:?}"))?;

        // Build a swap table for taking SExp objects we have line numbers for and
        // inserting them into the translated code, replacing the unlabeled ones.
        let mut swap_table = HashMap::new();
        build_swap_table_mut(&mut swap_table, &compiled_rc);
        let entries_to_replace: Vec<_> = swap_table
            .iter()
            .filter_map(|(hash, sexp)| {
                if let Some(symbol) = symbol_table.get(hash)
                    && let Some(range) = range_results.get(symbol)
                    && let sexp::SExp::Cons(_, a, b) = &sexp
                {
                    return Some((
                        hash.clone(),
                        sexp::SExp::Cons(range.0.clone(), a.clone(), b.clone()),
                    ));
                }
                None
            })
            .collect();
        for (h, e) in entries_to_replace.into_iter() {
            swap_table.insert(h, e);
        }
        Rc::new(relabel(&swap_table, &compiled_rc))
    };

    let symbols = Rc::new(symbol_table);
    let generator = Program::new(
        &mut CreateChialispSExp,
        range_results,
        filename,
        RcSExp(compiled),
        symbols.clone(),
    )?;
    Ok(CompileResult {
        object: generator.to_elf(output)?,
        symbols,
    })
}
