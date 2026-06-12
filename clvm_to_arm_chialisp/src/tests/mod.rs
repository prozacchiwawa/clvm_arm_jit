use std::collections::HashMap;
use std::fs;
use std::rc::Rc;

use chialisp::classic::clvm_tools::binutils::disassemble;
use chialisp::compiler::clvm::convert_from_clvm_rs;
use chialisp::compiler::sexp::SExp;
use chialisp::compiler::srcloc::Srcloc;
use clvmr::Allocator;

use clvm_to_arm_emulate::emu::{DynResult, Emu};
use clvm_to_arm_generate::code::TARGET_ADDR;
#[cfg(test)]
use clvm_to_arm_test::run_gdb;

use crate::compile;

#[cfg(test)]
fn compile_and_run(filename: &str, program: &str, env: &str) -> DynResult<Option<Rc<SExp>>> {
    let mut allocator = Allocator::new();
    let search_paths = Vec::new();
    let compiled = compile(&mut allocator, filename, program, "test.elf", &search_paths, env)?;
    let node_result = Emu::run_to_exit(
        &mut allocator,
        &compiled.object.object_file,
        TARGET_ADDR,
        compiled.symbols.clone(),
    )?;
    Ok(node_result.map(|r| {
        convert_from_clvm_rs(&mut allocator, Srcloc::start("*emu*"), r).expect("converted")
    }))
}

#[cfg(test)]
fn compile_and_gdb(
    filename: &str,
    program: &str,
    output: &str,
    env: &str,
    gdb_commands: &[&str],
) -> Result<String, String> {
    let mut allocator = Allocator::new();
    let search_paths = Vec::new();
    let compiled = compile(&mut allocator, filename, program, output, &search_paths, env)?;
    std::fs::write(&format!("{filename}.elf"), &compiled.object.object_file).unwrap();
    run_gdb(compiled.object, compiled.symbols.clone(), gdb_commands)
}

#[test]
fn test_run_to_exit_and_return_nil() {
    let mut allocator = Allocator::new();
    let elf = fs::read("../resources/tests/return_nil.elf").expect("should exist");
    let result = Emu::run_to_exit(
        &mut allocator,
        &elf,
        TARGET_ADDR,
        Rc::new(HashMap::default()),
    )
    .expect("should load")
    .unwrap();
    assert_eq!(disassemble(&allocator, result, None), "()");
}

#[test]
fn test_run_to_exit_and_return_pair() {
    let mut allocator = Allocator::new();
    let elf = fs::read("../resources/tests/return_cons.elf").expect("should exist");
    let result = Emu::run_to_exit(
        &mut allocator,
        &elf,
        TARGET_ADDR,
        Rc::new(HashMap::default()),
    )
    .expect("should load")
    .unwrap();
    assert_eq!(disassemble(&allocator, result, None), "(26729 . \"there\")");
}

#[test]
fn test_compile_and_run_simple_quoted_atom() {
    let result = compile_and_run("test.clsp", "(mod () \"hi there\")", "()")
        .expect("should run")
        .unwrap();
    assert_eq!(
        result,
        Rc::new(SExp::Atom(Srcloc::start("*test*"), b"hi there".to_vec()))
    );
}

#[test]
fn test_compile_and_run_cons() {
    let result = compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (c \"hi\" \"there\"))",
        "()",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "(26729 . 499967685221)");
}

#[test]
fn test_compile_and_run_apply_simple_1() {
    let result = compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (a 1 (q . \"toot\")))",
        "()",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "1953460084");
}

#[test]
fn test_compile_and_run_apply_simple_2() {
    let result = compile_and_run(
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
    let result = compile_and_run(
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
    let result = compile_and_run(
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
    let result = compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (f 99))",
        "()",
    )
    .expect("should run");
    assert!(result.is_none());
}

#[test]
fn test_compile_and_run_apply_simple_5() {
    let result = compile_and_run(
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
    let result = compile_and_run(
        "test.clsp",
        "(mod () (include *standard-cl-23*) (r 99))",
        "()",
    )
    .expect("should run");
    assert!(result.is_none());
}

#[test]
fn test_compile_and_run_apply_at() {
    let result = compile_and_run(
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
    let result = compile_and_run(
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
    let result = compile_and_run(
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
    let result = compile_and_run(
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
    let result = compile_and_run(
        "test.clsp",
        "(mod (A B) (include *standard-cl-23*) (defun F (A B) (+ 1 A B)) (F A B))",
        "(99 103)",
    )
    .expect("should run")
    .unwrap();
    assert_eq!(result.to_string(), "203");
}

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

#[test]
fn test_gdb_breakpoint_on_function_classic() {
    let result = compile_and_gdb(
        "test.clsp",
        "(mod (A)\n  (defun F (X Y) (+ X Y))\n  (F A 3)\n)",
        "test.elf",
        "(17)",
        &["set confirm off", "break F", "info breakpoints", "quit"],
    )
    .expect("should compile and load");
    eprintln!("result {result}");
    assert!(!result.contains("<MULTIPLE>"));
    assert!(result.contains("clsp:2"));
}
