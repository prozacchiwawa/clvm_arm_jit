use clvm_to_arm_rue::{Args, compile_rue_to_arm_elf};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct CmdArgs {
    #[arg(short, long)]
    output: String,

    #[arg(short, long)]
    source: String,

    #[arg(short, long)]
    env: String,
}

fn compile_rue_code(args: &CmdArgs) -> Result<(), String> {
    let compiled = compile_rue_to_arm_elf(&Args {
        env: args.env.clone(),
        filename: args.source.clone(),
        output: args.output.clone()
    }).map_err(|e| format!("error compiling rue code: {e:?}"))?;
    (|| -> Result<(), std::io::Error> {
        std::fs::write(&args.output, &compiled.object.object_file)?;
        std::fs::write(&format!("{}.clsp", args.output), compiled.object.synthetic_source.as_bytes())?;
        Ok(())
    })().map_err(|e| format!("error writing output: {e:?}"))?;
    Ok(())
}

fn main() {
    let args = CmdArgs::parse();
    if let Err(e) = compile_rue_code(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
