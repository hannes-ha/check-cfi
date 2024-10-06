use std::{collections::VecDeque, fs};

use clap::{Arg, Command};
use colored::Colorize;
use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, Register,
};
use object::{Object, ObjectSection};

const INSTRUCTION_BUFFER_SIZE: usize = 15;

fn read_file(path: &str) -> Vec<u8> {
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

/*
    A call instruction is considered "cfi-checked" if:
        - the value has ben compared (cmp) with another, static value.
        - the result of the comparison result in a branch to the call instruction OR to a ud1 instruction

            caviats:
        - the branch to the call instruction does not need to be direct, often it will point to instructions loading arguments.
             but no modifications to the call target should be made before the actual call
        - the comparison can be made on another register, holding the same value (ignore?)
*/

#[allow(dead_code)]
fn is_cfi_checked(icall: &Instruction, predecessors: &VecDeque<Instruction>) -> bool {
    // if this is not a call instruction, throw error
    if icall.mnemonic() != Mnemonic::Call {
        eprintln!("{:?}", icall);
        eprintln!("{:?}", predecessors);
        panic!("is_cfi_checked called on non-call instruction");
    }

    // call [rbp - 0xabc] might be needed as well
    // for now, we assume target is a register
    if icall.op0_kind() != OpKind::Register {
        eprintln!("{:?}", icall);
        eprintln!("{:?}", predecessors);
        panic!("is_cfi_checked called on non-register call instruction");
    }

    let target_reg = icall.op0_register();

    let mut friend_registers: Vec<Register> = Vec::new();

    let mut compared_register: Option<Register> = None;
    let mut jump_ip: Option<u64> = None;
    let mut valid_register: Option<Register> = None;

    for pred in predecessors {
        // if we run into another call instruction, something is wrong
        // handle this better later
        // just start over?
        if pred.is_call_near() || pred.is_call_far() {
            panic!("found another call within predecessors");
        }

        // add friends untill we find the compared register
        if compared_register.is_none() {
            match pred.mnemonic() {
                // way to remove friends might be needed
                Mnemonic::Mov => {
                    if pred.op1_kind() == OpKind::Register && pred.op1_register() == target_reg {
                        friend_registers.push(pred.op0_register());

                    // This is wierd, ugly and probably incorrect
                    } else if friend_registers.contains(&pred.op1_register()) {
                        friend_registers.push(pred.op0_register());
                    }
                }
                Mnemonic::Cmp => {
                    // if the comparison is made with a static value, this is now compared register
                    if pred.op1_kind() == OpKind::Immediate8to64 {
                        compared_register = Some(pred.op0_register());
                    }
                }
                _ => {}
            }
            continue;
        }

        // when compared register is found, next instruction must be a jump
        if jump_ip.is_none() {
            match pred.mnemonic() {
                // this can probably be different jump instructions
                Mnemonic::Jbe => {
                    jump_ip = Some(pred.ip());
                    continue;
                }
                _ => return false,
            }
        }

        // if we have a jump target, next instruction must be UD1
        if valid_register.is_none() {
            match pred.mnemonic() {
                Mnemonic::Ud1 => {
                    valid_register = compared_register;
                    continue;
                }
                _ => return false,
            }
        }

        // finally, we must not touch the valid register before the call
        for i in 0..pred.op_count() {
            if Some(pred.op_register(i)) == valid_register {
                return false;
            }
        }
    }

    // now we just need to check that the valid register is the same as the target register
    // or that the valid register is one of our friends
    if valid_register == Some(target_reg) {
        return true;
    }

    for friend in friend_registers {
        if valid_register == Some(friend) {
            return true;
        }
    }

    return false;
}

fn is_cfi_checked_2(icall: &Instruction, predecessors: &VecDeque<Instruction>) -> bool {
    // only keep instructions since last cmp
    let mut relevant_inst: VecDeque<_> = predecessors
        .iter()
        .rev()
        .take_while(|instr| instr.mnemonic() != Mnemonic::Cmp)
        .collect();

    // might need to allow distance here

    // reverse relevant instructions again
    // but keep as iterator

    // the instruction after the cmp should be a jump
    let jmp_target: u64;
    match relevant_inst.pop_back() {
        Some(instr) => {
            if instr.mnemonic() != Mnemonic::Jbe {
                return false;
            }
            jmp_target = instr.memory_displacement64();
        }
        None => return false,
    }

    // next instruction should be ud1
    match relevant_inst.pop_back() {
        Some(instr) => {
            if instr.mnemonic() != Mnemonic::Ud1 {
                return false;
            }
        }
        None => return false,
    }

    // now, the jump target should be passed
    // and the target register should not be touched

    let mut jump_target_passed = false;
    while let Some(instr) = relevant_inst.pop_back() {
        if instr.ip() == jmp_target {
            jump_target_passed = true;
        }

        // this might be unnessecary/overkill
        match icall.op0_kind() {
            OpKind::Register => {
                if instr.op0_register() == icall.op0_register() {
                    return false;
                }
            }
            OpKind::Memory => {
                if instr.memory_displacement64() == icall.memory_displacement64() {
                    return false;
                }
            }
            _ => {}
        }
    }

    jump_target_passed
}

fn disassembled_iced(code: &[u8]) {
    let base_offset = 0x1020;
    // set up iced
    let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
    decoder.set_ip(base_offset);

    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    formatter.options_mut().set_branch_leading_zeros(false);

    let mut predecessors = VecDeque::<Instruction>::new();

    // iterate instructions
    for instruction in decoder.into_iter() {
        let mut output = String::new();
        formatter.format(&instruction, &mut output);

        // find indirect calls
        if instruction.is_call_far_indirect() || instruction.is_call_near_indirect() {
            // if its relative to RIP or EIP, its fine (RIGHT?!)
            // we somehow need to remove the "indirect" calls to __cxa_finalize
            // are these simply DSOs?
            if !instruction.is_ip_rel_memory_operand() {
                if is_cfi_checked_2(&instruction, &predecessors) {
                    output = format!(
                        "{} {}",
                        output.green().bold(),
                        "<-- CFI checked call".green().bold()
                    );
                } else {
                    output = format!(
                        "{} {}",
                        output.red().bold(),
                        "<-- Unchecked call".red().bold()
                    );
                }
                // empty predecessors
                predecessors.clear();
            }
        }
        predecessors.push_back(instruction);

        // if length is above buffer size, pop the oldest
        if predecessors.len() > INSTRUCTION_BUFFER_SIZE {
            predecessors.pop_front();
        }
        println!("0x{:x}: {}", instruction.ip(), output);
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
    // let file_path = "/home/hannes/Kth/mex/check-cfi/test/input/cfi_indirect";
    let file_content = read_file(&file_path);
    disassembled_iced(&file_content);
}

// when we encounter a indirect call, we want to make sure that the target is sanitized
// we want to make sure that the call is preceded by
// 1. a cmp with something
// 2. a check of the result
// 3. a jmp to ud1 if check fails
