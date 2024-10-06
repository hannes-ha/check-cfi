use std::collections::{HashMap, VecDeque};

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use indicatif::ProgressStyle;

const INSTRUCTION_BUFFER_SIZE: usize = 15;
const ARGUMENT_LOADING_INSTRUCTION_COUNT: usize = 10;

/*
            idea:
        - To determine a call as cfi-checked, we require the following:
            - the target must have been compared to something else.
            - between the compare and the call, there should exist two branches
                - one leads to a ud1
                - the other leads to the call
            - the register/mem location may not be altered between the cmp and call.

            caviats:
        - the branch to the call instruction does not need to be direct, often it will point to instructions loading arguments.
             but no modifications to the call target should be made before the actual call
        - the actual santization is done in other registers, holding the same value
        - the comparison may be done with a "test" instruction.
        - the ud1 may be called by a jmp
*/

// allow unused
#[allow(dead_code)]
pub struct Analyzer {
    instructions: Vec<Instruction>,
    icalls: Vec<Instruction>,
    address_map: HashMap<u64, usize>,
    checked: Vec<Instruction>,
    unchecked: Vec<Instruction>,
    predecessors: VecDeque<Instruction>,
}

impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            instructions: Vec::new(),
            icalls: Vec::new(),
            address_map: HashMap::new(),
            checked: Vec::new(),
            unchecked: Vec::new(),
            predecessors: VecDeque::new(),
        }
    }
    pub fn disassemble(&mut self, code: &[u8], offset: u64) {
        let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
        decoder.set_ip(offset);

        let progress = indicatif::ProgressBar::new(code.len() as u64);
        progress.set_style(
            ProgressStyle::with_template("Dissasembling: [{bar} {percent}%]")
                .unwrap()
                .progress_chars("=>-"),
        );

        let mut i = 0;
        for instruction in decoder.iter() {
            self.instructions.push(instruction);
            self.address_map.insert(instruction.ip(), i);
            if instruction.is_call_far_indirect() || instruction.is_call_near_indirect() {
                if !instruction.is_ip_rel_memory_operand() {
                    self.icalls.push(instruction);
                }
            }
            i += 1;
            progress.inc(instruction.len() as u64);
        }

        progress.finish();
    }

    pub fn analyze(&mut self) {
        let progress = indicatif::ProgressBar::new(self.icalls.len() as u64);
        progress.set_style(
            ProgressStyle::with_template("Analyzing: [{bar} {percent}%]")
                .unwrap()
                .progress_chars("=>-"),
        );

        for icall in self.icalls.iter() {
            if self.is_cfi_checked(icall).is_ok() {
                self.checked.push(icall.clone());
            } else {
                self.unchecked.push(icall.clone());
            }
            progress.inc(1);
        }
        progress.finish();
    }

    pub fn get_results(&self) -> (&Vec<Instruction>, &Vec<Instruction>) {
        (&self.checked, &self.unchecked)
    }

    fn is_cfi_checked(&self, icall: &Instruction) -> Result<(), ()> {
        // look up the instructions index in the vector
        let Some(instruction_index) = self.address_map.get(&icall.ip()) else {
            return Err(());
        };

        // predecessor index is instruction_index - 15 (minimum 0)
        let predecessor_index = if *instruction_index > INSTRUCTION_BUFFER_SIZE {
            *instruction_index - INSTRUCTION_BUFFER_SIZE
        } else {
            0
        };

        // get predecessors by slicing 15 instructions from the instruction vector
        let Some(predecessors) = self.instructions.get(predecessor_index..*instruction_index)
        else {
            return Err(());
        };

        // println!("Instruction: {}", icall);
        // println!("icall register mnemonic: {:?}", icall.op0_register());

        // println!("Predecessors instruction count: {}", predecessors.len());
        // println!("Predecessors:");
        // for instr in predecessors {
            // println!("{}", instr);
        // }

        // save the predecessors up until the value of the call target is loaded
        let relevant_instructions = predecessors
            .iter()
            .rev()
            .take_while(|instruction| {
                if instruction.mnemonic() == Mnemonic::Mov {
                    match instruction.op0_kind() {
                        OpKind::Register => {
                            return instruction.op0_register() != icall.op0_register();
                        }
                        OpKind::Memory => {
                            return instruction.memory_displacement64()
                                != icall.memory_displacement64();
                        }
                        _ => return true,
                    }
                }
                true
            })
            .collect::<Vec<_>>();

        // println!(
            // "Relevant instruction count: {}",
            // relevant_instructions.len()
        // );

        let mut test_passed = false;
        let mut fail_branch_found = false;
        let mut call_branch_found = false;

        // println!();
        // println!();
        // println!();
        // we now iterate over the relevant instructions to find the two branches
        relevant_instructions.iter().rev().for_each(|instruction| {
            if instruction.mnemonic() == Mnemonic::Cmp || instruction.mnemonic() == Mnemonic::Test {
                test_passed = true;
            }

            if test_passed {
                // println!("Checking instruction: {}", instruction);
                if is_jump(instruction) {
                    // println!("JMP found");
                    // println!("Branch target: {}", instruction.near_branch_target());
                    // println!("icall target: {}", icall.ip());
                    if instruction.near_branch_target() == icall.ip() {
                        call_branch_found = true;
                    } else {
                        // println!("checking for ud1");
                        // look up the branch target in the address map
                        let branch_target_index = self
                            .address_map
                            .get(&instruction.near_branch_target())
                            .unwrap();

                        // println!("Branch target index: {}", branch_target_index);

                        // get the branch target instruction
                        let branch_target = self.instructions.get(*branch_target_index).unwrap();

                        //println!("Branch target instruction: {}", branch_target);

                        // check if the branch target is a ud1
                        if branch_target.mnemonic() == Mnemonic::Ud1 {
                            fail_branch_found = true;
                        }

                        // if not, we search for the call instruction within the next instructions
                        // get the iterator at this position
                        let mut instruction_iter =
                            self.instructions.iter().skip(*branch_target_index);

                        for _ in 0..ARGUMENT_LOADING_INSTRUCTION_COUNT {
                            let next_instruction = instruction_iter.next().unwrap();
                            if next_instruction.ip() == icall.ip() {
                                call_branch_found = true;
                                break;
                            }
                        }
                    }
                }
                if is_ud1(instruction) {
                    // println!("UD1 found");
                    fail_branch_found = true;
                }
            }
        });
        // println!("Test passed: {}", test_passed);
        // println!("Fail branch found: {}", fail_branch_found);
        // println!("Call branch found: {}", call_branch_found);

        if test_passed && fail_branch_found && call_branch_found {
            return Ok(());
        }

        return Err(());
    }
}



fn is_jump(instruction: &Instruction) -> bool {
    let mnemonic = instruction.mnemonic();
    return vec![
        Mnemonic::Jb,
        Mnemonic::Je,
        Mnemonic::Jbe,
        Mnemonic::Jl,
        Mnemonic::Jle,
        Mnemonic::Jno,
    ]
    .contains(&mnemonic);
}

fn is_ud1(instruction: &Instruction) -> bool {
    return instruction.mnemonic() == Mnemonic::Ud1;
}
