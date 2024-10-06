use std::fs;

use capstone::prelude::*;
use clap::{Arg, Command};
use object::{Object, ObjectSection, SectionKind};

extern crate capstone;

fn read_file(path: &str) -> Vec<u8> {
    // read binary
    let binary = fs::read(path).expect("Could not read file");

    // parse file
    let file = object::File::parse(&*binary).expect("Could not parse file.");

    // get text segment
    let text_segment = file
        .sections()
        .find(|section| section.kind() == SectionKind::Text)
        .expect("No text segment found.");

    // extract data
    let data = text_segment
        .data()
        .expect("Could not get data from section.");

    // return as vector
    Vec::from(data)
}

fn disassemble(code: &[u8]) {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true) // Enable detailed disassembly
        .build()
        .expect("Failed to create Capstone disassembler");
    let insns = cs.disasm_all(code, 0x1000).expect("Failed to disassemble"); // Assuming 0x1000 as the base address
    for insn in insns.iter() {
        println!(
            "0x{:x}: {:6} {}",
            insn.address(),
            insn.mnemonic().unwrap_or(""),
            insn.op_str().unwrap_or("")
        );
    }
}

fn main() {
    let matches = Command::new("Hello world")
        .arg(
            Arg::new("FILE")
                .help("Sets the input file to use")
                .required(true)
                .index(1),
        )
        .get_matches();
    let file_path = matches.get_one::<String>("FILE").expect("FILE is required");

    let file_content = read_file(&file_path);

    disassemble(&file_content);
}
