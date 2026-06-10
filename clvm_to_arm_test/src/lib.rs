use std::collections::HashMap;
use std::io::Write;
use std::net::TcpListener;
use std::sync::mpsc;
use std::rc::Rc;
use std::thread;

use subprocess::Exec;
use tempfile::NamedTempFile;

use clvm_to_arm_generate::code::{ElfObject, TARGET_ADDR};
use clvm_to_arm_emulate::emu::Emu;
use clvm_to_arm_emulate::emu_stub::run_stub;

pub fn run_gdb(
    object: ElfObject,
    symbols: Rc<HashMap<String, String>>,
    gdb_commands: &[&str],
) -> Result<String, String> {
    let elf_out = NamedTempFile::new().unwrap();
    elf_out.as_file().write(&object.object_file).unwrap();
    let (gdb_remote_sender, gdb_remote_receiver) = mpsc::channel();
    let symbols_ref: &HashMap<String, String> = &symbols;
    let symbols_copy = symbols_ref.clone();
    let _gdb_thread = thread::spawn(move || {
        let mut emu = Emu::new(
            &object.object_file,
            TARGET_ADDR,
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
    let result = Exec::cmd("gdb-multiarch").args(&gdb_command_line).capture().unwrap().stdout_str();
    Ok(result)
}
