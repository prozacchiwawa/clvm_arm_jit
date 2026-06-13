Summary
====

A code generator and emulator which write very simple arm code that allows gdb to observe
and participate in clvm code evaluation.

You can compile instrumented chialisp and rue programs and observe them using all the tools
available in gdb-multiarch.

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

Details
====

An elf object file with 32-bit arm code is generated from the clvm code given to
the clvm_to_arm_generate::code::Program object along with as much information as
can be collected from the source code, in the form of associations between clvm
forms and source locations. Program::to_elf generates arm code from the clvm
code to produce the same result. Only a few instructions are actually generated
as arm code with the rest being dispatched using an svc instruction. The
accompanying emulator implements a few svc forms specially.

Program structure:
---

The entry point _start at 0x1000 loads a pointer to an environment prepared in
ram from r1. The program contains a grows up heap pointer at _run, which the
program loads the address of and puts in r5. r7 is used as a current environment
pointer across the whole program so it is loaded from r1. The program then calls
the function which was generated from the whole clvm expression given to the
generator. Upon return, it does svc 4 (print) and then svc 0 (done).

The main body of the program contains each clvm expression's code indexed by
hash and occurrence.  It's possible for different clvm expressions with the same
clvm value to have different line number information, so each reachable occurrence
appears separately with its own dwarf (line number) information.

Because environment references can be dynamic, the code generator is
conservative. It generates arm code for every subexpression in the clvm code
given, regardless of whether it is normally executed as code has code generated
as though it might be. Dwarf line number and argument decoding information can
only be provided for code that is present in the elf executable, so this
maximizes gdb's ability to show information.

svc 1 implements throw. When it is used for an (x ...) operator, it also prints
the arguments to the x operator to gdb as a console notification.

The emulator supports rue style "debug_print" and inline (all "$print$" ...)
debug forms and sends the data to gdb as a console notification when these
appear. If you configure gdb not to stop on SIGUSR1, these notifications won't
interrupt the program run.

In memory clvm:
---

An atom is either a null pointer (nil) or a pointer to an odd valued word. The
word pointed to contains (2 * len) | 1, followed by the byte data for the atom.

A cons is any non-nil pointer to an even pointer value.  The cons contains 2
pointers, which are simply pointers to the head and tail elements.  The python
code, support/gdb_print_sexp.py decodes clvm data in this way so that gdb can
show structured clvm data during argument decoding at other times.  Input to the
clvm operation currently being carried out is in $r0, which you can print as
clvm data in gdb like this: "print (word)$r0".  This may especially be useful
when examining data going into complex operators.  the svc 3 instruction asks
the emulator to perform an arbitrary clvm operator.  The operator is in $r0 and
the argument values are in $r1.
