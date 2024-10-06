use core::fmt;
use std::{fs, io};

use iced_x86::{Formatter, Instruction, IntelFormatter};
use object::{Object, ObjectSection};

#[derive(Debug)]
pub(crate) struct FileReadError {
    msg: String,
}
impl fmt::Display for FileReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}
impl FileReadError {
    fn new(msg: String) -> FileReadError {
        FileReadError {
            msg: msg.to_string(),
        }
    }
}

impl From<object::Error> for FileReadError {
    fn from(err: object::Error) -> Self {
        FileReadError::new(err.to_string())
    }
}

impl From<io::Error> for FileReadError {
    fn from(err: io::Error) -> Self {
        FileReadError::new(err.to_string())
    }
}

pub fn read_file(path: &str) -> Result<(Vec<u8>, u64), FileReadError> {
    // read binary
    let binary = fs::read(path)?;

    // parse file
    let file = object::File::parse(&*binary)?;

    // get text segment
    let text_segment = file
        .sections()
        .find(|section| section.name().unwrap() == ".text")
        .expect("Could not find .text section");

    // get address of segment
    let adress = text_segment.address();

    // extract data
    let data = text_segment.data()?;

    // return as vector
    Ok((Vec::from(data), adress))
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
    println!();
}
