Quick Start (rue)
====

    cargo build
    cargo run --bin=clvm_to_arm_build_rue -- --output factorial.elf --env '(5)' --source ./resources/tests/factorial.rue 
    cargo run --bin=clvm_to_arm_serve -- --elf factorial.elf &
    ...
    Waiting for a GDB connection on Ok(127.0.0.1:46055)...
    gdb-multiarch --ex "source support/gdb_print_sexp.py" --ex "dir ./resources/tests" --ex "b factorial" -ex "target remote :46055" ./factorial.elf
