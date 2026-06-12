use std::collections::HashMap;
use std::rc::Rc;

use clvmr::Allocator;
use clvm_to_arm_generate::code::{ElfObject, Program, TARGET_ADDR};
use tempfile::NamedTempFile;

use chialisp::classic::clvm_tools::stages::stage_0::{DefaultProgramRunner, TRunProgram};
use chialisp::compiler::compiler::{compile_file, DefaultCompilerOpts};
use chialisp::compiler::comptypes::CompilerOpts;
use chialisp::compiler::debug::build_symbol_table_mut;
use chialisp::compiler::dialect::AcceptedDialect;
use chialisp::compiler::frontend::frontend;
use chialisp::compiler::sexp::{decode_string, parse_sexp};
use chialisp::compiler::srcloc::Srcloc;

use crate::sexp_trait::{CreateChialispSExp, RcSExp, SrclocWrap};

pub mod sexp_trait;

#[cfg(test)]
pub mod tests;

pub struct CompileResult {
    pub object: ElfObject,
    pub symbols: Rc<HashMap<String, String>>,
}

pub fn compile(
    allocator: &mut Allocator,
    filename: &str,
    program: &str,
    search_paths: &[String],
    env: &str,
) -> Result<CompileResult, String> {
    let srcloc = Srcloc::start(filename);
    let env_parsed = parse_sexp(srcloc.clone(), env.bytes()).map_err(|e| format!("{e:?}"))?;
    let mut symbol_table = HashMap::new();
    let runner: Rc<dyn TRunProgram> = Rc::new(DefaultProgramRunner::new());
    let opts = Rc::new(DefaultCompilerOpts::new(filename))
        .set_dialect(AcceptedDialect {
            stepping: Some(23),
            strict: true,
            int_fix: true,
            extra_numeric_constants: false,
        })
        .set_optimize(true)
        .set_search_paths(search_paths)
        .set_frontend_opt(false);

    let parsed_program = parse_sexp(srcloc.clone(), program.bytes())
        .map_err(|e| format!("failed to parse chialisp program {filename}: {e:?}"))?;
    let fe = frontend(opts.clone(), &parsed_program)
        .map_err(|e| format!("failed to compose frontend program: {e:?}"))?;
    let range_results: HashMap<String, SrclocWrap> = fe
        .compileform()
        .helpers
        .iter()
        .map(|h| (decode_string(h.name()), SrclocWrap(h.loc())))
        .collect();

    let compiled = compile_file(allocator, runner, opts, program, &mut symbol_table)
        .map_err(|e| format!("{e:?}"))?
        .to_sexp();
    build_symbol_table_mut(&mut symbol_table, &compiled);
    let tmpfile = NamedTempFile::new().map_err(|e| format!("{e:?}"))?;
    let tmpname = tmpfile.path().to_str().unwrap().to_string();
    let symbols = Rc::new(symbol_table);
    let generator = Program::new(
        &mut CreateChialispSExp,
        range_results,
        filename,
        &tmpname,
        RcSExp(Rc::new(compiled)),
        RcSExp(env_parsed[0].clone()),
        TARGET_ADDR,
        symbols.clone(),
    )?;
    Ok(CompileResult {
        object: generator.to_elf(&tmpname)?,
        symbols,
    })
}
