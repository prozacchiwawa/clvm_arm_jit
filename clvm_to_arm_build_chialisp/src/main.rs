use clap::Parser;
use clvmr::Allocator;

use clvm_to_arm_chialisp::compile;

#[derive(Parser, Debug)]
#[command(version, about)]
struct CmdArgs {
    #[arg(short, long)]
    output: String,

    #[arg(short, long)]
    source: String,

    #[arg(short, long)]
    include: Vec<String>,

    #[arg(short, long)]
    env: String,
}

fn do_compile(args: &CmdArgs) -> Result<(), String> {
    let mut allocator = Allocator::new();
    let program = std::fs::read_to_string(&args.source).map_err(|e| format!("{e:?}"))?;
    let compiled = compile(
        &mut allocator,
        &args.source,
        &program,
        &args.output,
        &args.include,
        &args.env,
    )?;
    std::fs::write(&args.output, &compiled.object.object_file).map_err(|e| format!("{e:?}"))?;
    Ok(())
}

fn main() {
    let args = CmdArgs::parse();
    if let Err(e) = do_compile(&args) {
        eprintln!("error compiling: {e:?}");
        std::process::exit(1);
    }
}
