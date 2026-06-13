use std::collections::HashMap;
use std::io::Write;
use std::net::TcpListener;
use std::rc::Rc;
use std::sync::mpsc;
use std::thread;

use subprocess::Exec;
use tempfile::NamedTempFile;

use clvm_to_arm_emulate::emu::Emu;
use clvm_to_arm_emulate::emu_stub::run_stub;
use clvm_to_arm_generate::code::ElfObject;

use clvmr::Allocator;
use chialisp::classic::clvm_tools::binutils::assemble;

pub fn run_gdb(
    object: ElfObject,
    env: &str,
    symbols: Rc<HashMap<String, String>>,
    gdb_commands: &[&str],
) -> Result<(String, String), String> {
    let elf_out = NamedTempFile::new().unwrap();
    elf_out.as_file().write_all(&object.object_file).unwrap();
    let (gdb_remote_sender, gdb_remote_receiver) = mpsc::channel();
    let symbols_ref: &HashMap<String, String> = &symbols;
    let symbols_copy = symbols_ref.clone();
    let env_string = env.to_string();
    let _gdb_thread = thread::spawn(move || {
        let mut allocator = Allocator::new();
        let env_node = assemble(&mut allocator, &env_string).unwrap();
        let mut emu = Emu::new(
            &mut allocator,
            &object.object_file,
            env_node,
            Rc::new(symbols_copy)
        ).unwrap();
        let sockaddr = "127.0.0.1:0";
        let sock = TcpListener::bind(sockaddr).unwrap();
        let local_addr = sock.local_addr().unwrap();
        gdb_remote_sender.send(local_addr.port()).unwrap();
        let (stream, _) = sock.accept().unwrap();
        run_stub(Box::new(stream), &mut emu).unwrap();
    });
    let port = gdb_remote_receiver.recv().unwrap();
    let mut gdb_command_line = vec![];
    for command in gdb_commands.iter() {
        gdb_command_line.push("--ex".to_string());
        if *command == "$REMOTE" {
            gdb_command_line.push(format!("target remote :{port}"));
        } else {
            gdb_command_line.push(command.to_string());
        }
    }
    gdb_command_line.push(elf_out.path().display().to_string());
    let result_obj = Exec::cmd("gdb-multiarch")
        .args(&gdb_command_line)
        .capture()
        .unwrap();
    let stderr = result_obj.stderr_str();
    let stdout = result_obj.stdout_str();
    Ok((stdout, stderr))
}
