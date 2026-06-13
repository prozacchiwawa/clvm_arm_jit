use std::collections::HashMap;
use std::fs;
use std::rc::Rc;

use clap::Parser;

use clvm_to_arm_emulate::emu::Emu;
use clvm_to_arm_emulate::emu_stub::{run_stub, start_stub};
use clvm_to_arm_generate::code::TARGET_ADDR;

use chialisp::classic::clvm_tools::binutils::assemble;
use clvmr::Allocator;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    elf: String,

    #[arg(short, long)]
    arg: String,

    #[arg(short, long)]
    symbols: Option<String>,

    #[arg(short, long)]
    port: Option<i32>,
}

fn run_emu_stub(args: &Args) -> Result<(), String> {
    let elf_prog = fs::read(&args.elf).map_err(|e| format!("{e:?}"))?;
    let symbols = if let Some(symbols) = &args.symbols {
        let sym_raw = fs::read_to_string(symbols).map_err(|e| format!("{e:?}"))?;
        let result: HashMap<String, String> =
            serde_json::from_str(&sym_raw).map_err(|e| format!("{e:?}"))?;
        result
    } else {
        HashMap::default()
    };
    let mut allocator = Allocator::new();
    let env_node = assemble(&mut allocator, &args.arg).map_err(|e| format!("{e:?}"))?;
    let mut emu =
        Emu::new(
            &mut allocator,
            &elf_prog,
            env_node,
            TARGET_ADDR,
            Rc::new(symbols)
        ).map_err(|e| format!("{e:?}"))?;

    let (addr, connection) =
        start_stub(args.port.map(|p| p as u16)).map_err(|_e| "error starting stub".to_string())?;
    println!("{addr:?}");
    run_stub(connection, &mut emu)
}

pub fn main() {
    let args = Args::parse();
    if let Err(e) = run_emu_stub(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
