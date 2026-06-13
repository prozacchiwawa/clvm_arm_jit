Quick Start (rue)
====

    cargo build
    cargo run --bin=clvm_to_arm_build_rue -- --output factorial.elf --source ./resources/tests/factorial.rue 
    cargo run --bin=clvm_to_arm_serve -- --elf factorial.elf --arg '(5)' --port 9901 &
    ...
    Waiting for a GDB connection on Ok(127.0.0.1:9901)...
    gdb-multiarch --ex "source support/gdb_print_sexp.py" --ex "dir ./resources/tests" --ex "break factorial" -ex "target remote :9901" ./factorial.elf

Quick Start (chialisp)
====

    cargo build
    cargo run --bin=clvm_to_arm_build_chialisp -- --output test.elf --source ./resources/tests/test.clsp
    cargo run --bin=clvm_to_arm_serve -- --elf test.elf --arg '(3 7)' --port 9901 &
    ...
    Waiting for a GDB connection on Ok(127.0.0.1:9901)...
    gdb-multiarch --ex "source support/gdb_print_sexp.py" --ex "dir ./resources/tests" --ex "break F" -ex "target remote :9901" ./test.elf
