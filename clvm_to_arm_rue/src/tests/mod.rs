use clvmr::Allocator;

use chialisp::classic::clvm_tools::binutils::disassemble;
use clvm_to_arm_emulate::emu::Emu;
use clvm_to_arm_test::run_gdb;

use crate::{Args, compile_rue_to_arm_elf};

use chialisp::classic::clvm_tools::binutils::assemble;

#[test]
fn test_rue_compile_and_run_as_arm() {
    let output = "factorial.rue.elf";
    let compiled = compile_rue_to_arm_elf(&Args {
        filename: "../resources/tests/factorial.rue".to_string(),
        output: output.to_string(),
    })
    .unwrap();
    let mut allocator = Allocator::new();
    let env_node = assemble(&mut allocator, "(5)").unwrap();
    // std::fs::write(output, &compiled.object.object_file).unwrap();
    let result = Emu::run_to_exit(
        &mut allocator,
        &compiled.object.object_file,
        env_node,
        compiled.symbols,
    )
    .unwrap();
    assert_eq!(
        result.map(|result| disassemble(&allocator, result, None)),
        Some("120".to_string())
    );
}

#[test]
fn test_rue_assert_succeed() {
    let output = "test_assert.rue.elf";
    let compiled = compile_rue_to_arm_elf(&Args {
        filename: "../resources/tests/test_assert.rue".to_string(),
        output: output.to_string(),
    })
    .unwrap();
    let mut allocator = Allocator::new();
    let env_node = assemble(&mut allocator, "(5 3)").unwrap();
    // std::fs::write(output, &compiled.object.object_file).unwrap();
    let result = Emu::run_to_exit(
        &mut allocator,
        &compiled.object.object_file,
        env_node,
        compiled.symbols,
    )
    .unwrap();
    assert_eq!(
        result.map(|result| disassemble(&allocator, result, None)),
        Some("()".to_string())
    );
}

#[test]
fn test_rue_assert_fail() {
    let output = "test_assert.rue.elf";
    let compiled = compile_rue_to_arm_elf(&Args {
        filename: "../resources/tests/test_assert.rue".to_string(),
        output: output.to_string(),
    })
    .unwrap();

    std::fs::write(output, &compiled.object.object_file).unwrap();
    let (result, _) = run_gdb(
        compiled.object,
        "(16384 19)",
        compiled.symbols,
        &[
            "set confirm off",
            "set width 1000000",
            "dir ../resources/tests",
            "$REMOTE",
            "source ../support/gdb_print_sexp.py",
            "cont",
            "bt",
            "quit",
        ],
    )
    .unwrap();
    eprintln!("{result}");
    let found_idx = result.find("Program received signal SIGABRT").unwrap();
    let end_idx = result.find("Detaching").unwrap();
    let must_have_result = std::fs::read_to_string("../resources/tests/rue_assert_fail.txt")
        .unwrap()
        .trim()
        .to_string();
    let use_result = result[found_idx..end_idx].trim().to_string();
    assert_eq!(must_have_result, use_result);
}

#[test]
fn test_rue_debug() {
    let output = "test_debug.rue.elf";
    let compiled = compile_rue_to_arm_elf(&Args {
        filename: "../resources/tests/test_debug.rue".to_string(),
        output: output.to_string(),
    })
    .unwrap();

    std::fs::write(output, &compiled.object.object_file).unwrap();
    let (_, stderr) = run_gdb(
        compiled.object,
        "(16384 19)",
        compiled.symbols,
        &[
            "set confirm off",
            "handle SIGUSR1 nostop",
            "set width 1000000",
            "dir ../resources/tests",
            "$REMOTE",
            "source ../support/gdb_print_sexp.py",
            "cont",
            "bt",
            "quit",
        ],
    )
    .unwrap();
    for num in 0..4 {
        let want = format!(
            "DEBUG: (b'test_debug.rue:2:3' (b'check_div_by(' 16384 {} 41))",
            19 - num
        );
        assert!(stderr.contains(&want));
    }
}
