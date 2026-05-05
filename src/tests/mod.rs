use std::collections::HashMap;
use std::rc::Rc;

use clvmr::Allocator;
use chialisp::classic::clvm_tools::stages::stage_0::{DefaultProgramRunner, TRunProgram};
use chialisp::compiler::clvm::convert_from_clvm_rs;
use chialisp::compiler::comptypes::CompilerOpts;
use chialisp::compiler::compiler::{DefaultCompilerOpts, compile_file};
use chialisp::compiler::debug::build_symbol_table_mut;
use chialisp::compiler::dialect::AcceptedDialect;
use chialisp::compiler::frontend::frontend;
use chialisp::compiler::sexp::{SExp, decode_string, parse_sexp};
use chialisp::compiler::srcloc::Srcloc;
use tempfile::NamedTempFile;

use crate::code::{Program, TARGET_ADDR};
use crate::emu::{DynResult, Emu};

pub mod sexp_trait;
use crate::tests::sexp_trait::CreateChialispSExp;

#[cfg(test)]
fn compile_and_run(filename: &str, program: &str, env: &str) -> DynResult<Option<Rc<SExp>>> {
    let srcloc = Srcloc::start(filename);
    let env_parsed = parse_sexp(srcloc.clone(), env.bytes()).expect("should parse");
    let mut allocator = Allocator::new();
    let mut symbol_table = HashMap::new();
    let runner: Rc<dyn TRunProgram> = Rc::new(DefaultProgramRunner::new());
    let search_paths = vec![];
    let opts = Rc::new(DefaultCompilerOpts::new(filename))
        .set_dialect(AcceptedDialect {
            stepping: Some(23),
            strict: true,
            int_fix: true,
            extra_numeric_constants: false,
        })
        .set_optimize(true)
        .set_search_paths(&search_paths)
        .set_frontend_opt(false);

    let parsed_program = parse_sexp(srcloc.clone(), program.bytes())
        .map_err(|e| format!("failed to parse chialisp program {filename}"))?;
    let fe = frontend(opts.clone(), &parsed_program)
        .map_err(|e| format!("failed to compose frontend program"))?;
    let range_results: HashMap<String, Srcloc> = fe
        .compileform()
        .helpers
        .iter()
        .map(|h| (decode_string(h.name()), h.loc()))
        .collect();

    let compiled = compile_file(&mut allocator, runner, opts, program, &mut symbol_table)
        .expect("should compile")
        .to_sexp();
    build_symbol_table_mut(&mut symbol_table, &compiled);
    let tmpfile = NamedTempFile::new().expect("should be able to make a temp file");
    let tmpname = tmpfile.path().to_str().unwrap().to_string();
    let symbols = Rc::new(symbol_table);
    let generator = Program::new::<CreateChialispSExp>(
        range_results,
        filename,
        &tmpname,
        Rc::new(compiled),
        env_parsed[0].clone(),
        TARGET_ADDR,
        symbols.clone(),
    )
        .expect("should be generatable");
    let elf_data = generator.to_elf(&tmpname).expect("should generate");
    let node_result = Emu::run_to_exit(&mut allocator, &elf_data.object_file, TARGET_ADDR, symbols)?;
    Ok(node_result.map(|r| {
        convert_from_clvm_rs(&mut allocator, Srcloc::start("*emu*"), r).expect("converted")
    }))
}

/*
#[test]
fn test_run_to_exit_and_return_nil() {
    let elf = fs::read("resources/tests/armjit/return_nil.elf").expect("should exist");
    let result = Emu::run_to_exit(&elf, TARGET_ADDR, Rc::new(HashMap::default()))
        .expect("should load")
        .unwrap();
    assert_eq!(result.to_string(), "()");
}

#[test]
fn test_run_to_exit_and_return_pair() {
    let elf = fs::read("resources/tests/armjit/return_cons.elf").expect("should exist");
    let result = Emu::run_to_exit(&elf, TARGET_ADDR, Rc::new(HashMap::default()))
        .expect("should load")
        .unwrap();
    assert_eq!(result.to_string(), "(hi . there)");
}

#[test]
fn test_compile_and_run_simple_quoted_atom() {
    let result = Emu::compile_and_run("test.clsp", "(mod () \"hi there\")", "()")
        .expect("should run")
        .unwrap();
    assert_eq!(
        result,
        Rc::new(SExp::Atom(Srcloc::start("*test*"), b"hi there".to_vec()))
    );
}

#[test]
fn test_compile_and_run_cons() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (c \"hi\" \"there\"))",
        "()",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "(hi . there)");
}

#[test]
fn test_compile_and_run_apply_simple_1() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (a 1 (q . \"toot\")))",
        "()",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "toot");
}

#[test]
fn test_compile_and_run_apply_simple_2() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (a 1 @))",
        "37777",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "37777");
}

#[test]
fn test_compile_and_run_apply_simple_3() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (a (q 4 (1 . 1) (1 . 2)) @))",
        "()",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "(1 . 2)");
}

#[test]
fn test_compile_and_run_apply_simple_4() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (f (q 1 2)))",
        "()",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "1");
}

#[test]
fn test_compile_and_run_apply_simple_4_fail() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (f 99))",
        "()",
    )
    .expect("should run");
    assert!(result.is_none());
}

#[test]
fn test_compile_and_run_apply_simple_5() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (r (q 1 2)))",
        "()",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "(2)");
}

#[test]
fn test_compile_and_run_apply_simple_6() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (r 99))",
        "()",
    )
    .expect("should run");
    assert!(result.is_none());
}

#[test]
fn test_compile_and_run_apply_at() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod (A) (include *standard-cl-23*) @)",
        "(19)",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "(19)");
}

#[test]
fn test_compile_and_run_apply_path() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod (A) (include *standard-cl-23*) A)",
        "(19)",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "19");
}

#[test]
fn test_compile_and_run_apply_simple_op() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod (A B) (include *standard-cl-23*) (+ A B))",
        "(99 103)",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "202");
}

#[test]
fn test_compile_and_run_apply_simple_op1() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod (A B) (include *standard-cl-23*) (+ 1 A B))",
        "(99 103)",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "203");
}

#[test]
fn test_compile_and_run_apply_simple_function_0() {
    let result = Emu::compile_and_run(
        "test.clsp",
        "(mod (A B) (include *standard-cl-23*) (defun F (A B) (+ 1 A B)) (F A B))",
        "(99 103)",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "203");
}
*/

#[test]
fn test_compile_and_run_apply_function_1() {
    let result = compile_and_run(
        "test.clsp",
        "(mod (A) (include *standard-cl-23*) (defun F (A) (+ 1 A)) (F A))",
        "(17)",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "18");
}
