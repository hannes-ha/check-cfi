use std::fs;

use iced_x86::{Formatter, Instruction, IntelFormatter};
use object::{Object, ObjectSection};

pub fn read_file(path: &str) -> (Vec<u8>, u64) {
    // read binary
    let binary = fs::read(path).expect("Could not read file");

    // parse file
    let file = object::File::parse(&*binary).expect("Could not parse file.");

    // get text segment
    let text_segment = file
        .sections()
        .find(|section| section.name().unwrap() == ".text")
        .expect("No text segment found.");

    // get address of segment
    let adress = text_segment.address();

    // extract data
    let data = text_segment
        .data()
        .expect("Could not get data from .text section.");

    // return as vector
    (Vec::from(data), adress)
}

pub fn print_instruction(instr: &Instruction, formatter: &mut IntelFormatter) {
    let mut output = String::new();
    formatter.format(instr, &mut output);
    println!("0x{:x} {}", instr.ip(), output);
}

pub fn print_results(checked: &Vec<Instruction>, unchecked: &Vec<Instruction>, verbose: bool) {
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    formatter.options_mut().set_branch_leading_zeros(false);

    println!(
        "Found {} checked and {} unchecked indirect calls",
        checked.len(),
        unchecked.len()
    );

    if verbose {
        println!("---Unchecked:---");
        for instr in unchecked {
            print_instruction(&instr, &mut formatter);
        }
        println!("---Checked:---");
        for instr in checked {
            print_instruction(&instr, &mut formatter);
        }
    }
}
