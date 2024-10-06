use std::{fs::File, io::{self, Read}, path::Path};

use capstone::prelude::*; 
use clap::{Arg, Command};

extern crate capstone;

fn read_binary_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> { 
    let mut file = File::open(path)?; 
    let mut buffer = Vec::new(); 
    file.read_to_end(&mut buffer)?; 
    Ok(buffer) 
}

fn disassemble(code: &[u8]) { 
    let cs = Capstone::new() 
        .x86() 
        .mode(arch::x86::ArchMode::Mode64) 
        .syntax(arch::x86::ArchSyntax::Intel) 
        .detail(true)  // Enable detailed disassembly 
        .build() 
        .expect("Failed to create Capstone disassembler"); 
    let insns = cs.disasm_all(code, 0x1000).expect("Failed to disassemble");  // Assuming 0x1000 as the base address 
    for insn in insns.iter() { 
        println!("0x{:x}: {:6} {}", insn.address(), insn.mnemonic().unwrap_or(""), insn.op_str().unwrap_or("")); 
    } 


}

fn main() {
    let matches = Command::new("Hello world") 
        .arg(Arg::new("FILE") 
             .help("Sets the input file to use") 
             .required(true) 
             .index(1)) 
        .get_matches(); 
    let file_path = matches.get_one::<String>("FILE").expect("FILE is required"); 
    let binary_data = read_binary_file(file_path).expect("Failed to read binary file");    

    disassemble(&binary_data);
}
