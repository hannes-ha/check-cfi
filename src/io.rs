use core::fmt;
use std::{collections::HashMap, fs, io};

use iced_x86::{Formatter, Instruction, IntelFormatter};
use object::{Object, ObjectSection, ObjectSymbol};

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

pub fn read_file(path: &str) -> Result<(Vec<u8>, u64, HashMap<u64, String>), FileReadError> {
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

    let mut symbols = HashMap::<u64, String>::new();
    for dyn_sym in file.symbols() {
        match dyn_sym.name() {
            Ok(name) => {
                symbols.insert(dyn_sym.address(), name.to_string());
            }
            _ => {}
        }
    }
    // return as vector
    Ok((Vec::from(data), adress, symbols))
}

pub fn print_instruction(
    instr: &Instruction,
    message: String,
    symbol: String,
    format: &Option<String>,
    formatter: &mut IntelFormatter,
) {
    let mut output = String::new();

    formatter.format(instr, &mut output);
    match format.as_deref() {
        Some("csv") => {
            println!("0x{:x},{},{},{}", instr.ip(), output, symbol, message)
        }
        _ => println!(
            "0x{:x} {:<30} {:<40} {}",
            instr.ip(),
            output,
            symbol,
            message
        ),
    }
}

pub fn print_results(
    checked: &Vec<Instruction>,
    unchecked: &Vec<(Instruction, String)>,
    print_checked: bool,
    print_unchecked: bool,
    format: &Option<String>,
    symbol_map: &HashMap<u64, String>,
) {
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    formatter.options_mut().set_branch_leading_zeros(false);

    println!(
        "Found {} checked and {} unchecked indirect calls",
        checked.len(),
        unchecked.len()
    );

    if print_unchecked {
        println!("---Unchecked:---");
        for (instr, msg) in unchecked {
            let symbol = match symbol_map.get(&instr.ip()) {
                Some(str) => str.to_string(),
                _ => "".to_string(),
            };
            print_instruction(
                &instr,
                msg.to_string(),
                symbol.to_string(),
                format,
                &mut formatter,
            );
        }
    }

    if print_checked {
        println!("---Checked:---");
        for instr in checked {
            let symbol = match symbol_map.get(&instr.ip()) {
                Some(str) => str.to_string(),
                _ => "".to_string(),
            };
            print_instruction(&instr, "".to_string(), symbol, format, &mut formatter);
        }
    }
    println!();
}

pub fn progress_bar(len: u64, msg: &str) -> indicatif::ProgressBar {
    let progress = indicatif::ProgressBar::new(len);
    let content = format!("{:>15}", msg) + ": [{bar} {percent}%]";
    progress.set_style(
        indicatif::ProgressStyle::with_template(&content)
            .unwrap()
            .progress_chars("=>-"),
    );
    return progress;
}
