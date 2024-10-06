use std::fs;

use object::{Object, ObjectSection};

pub fn read_file(path: &str) -> Vec<u8> {
    // read binary
    let binary = fs::read(path).expect("Could not read file");

    // parse file
    let file = object::File::parse(&*binary).expect("Could not parse file.");

    // get text segment
    let text_segment = file
        .sections()
        .find(|section| section.name().unwrap() == ".text")
        .expect("No text segment found.");

    // extract data
    let data = text_segment
        .data()
        .expect("Could not get data from section.");

    // return as vector
    Vec::from(data)
}
