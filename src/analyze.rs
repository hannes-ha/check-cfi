use core::panic;
use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use indicatif::ProgressStyle;

const INSTRUCTION_BUFFER_SIZE: usize = 40;
const ARGUMENT_LOADING_INSTRUCTION_COUNT: usize = 20;
const DEBUGGING_IP: u64 = 0x28d3089;

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
}

impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            instructions: Vec::new(),
            icalls: Vec::new(),
            address_map: HashMap::new(),
            checked: Vec::new(),
            unchecked: Vec::new(),
        }
    }
    pub fn disassemble(&mut self, code: &[u8], offset: u64) {
        let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
        decoder.set_ip(offset);

        let progress = indicatif::ProgressBar::new(code.len() as u64);
        progress.set_style(
            ProgressStyle::with_template("Disassembling: [{bar} {percent}%]")
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
            match icall.op0_kind() {
                OpKind::Register => match self.is_cfi_checked_reg(icall) {
                    Ok(_) => self.checked.push(icall.clone()),
                    _ => self.unchecked.push(icall.clone()),
                },
                _ => self.unchecked.push(icall.clone()),
            }
            progress.inc(1);
        }
        progress.finish();
    }

    pub fn get_results(&self) -> (&Vec<Instruction>, &Vec<Instruction>) {
        (&self.checked, &self.unchecked)
    }

    fn is_cfi_checked_reg(&self, icall: &Instruction) -> Result<(), ()> {
        if icall.op0_kind() != OpKind::Register {
            panic!("Expected register as operand");
        }
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

        // save the predecessors up until the value of the call target is loaded
        let relevant_instructions = predecessors
            .iter()
            .rev()
            .take_while(|instruction| {
                match instruction.mnemonic() {
                    // stop if we run in to another call and we are using RAX for our call
                    Mnemonic::Call => return icall.op0_register() != Register::RAX,
                    // stop where the call target is loaded
                    Mnemonic::Mov => {
                        return !(instruction.op0_kind() == OpKind::Register
                            && instruction.op0_register() == icall.op0_register())
                    }
                    _ => return true,
                }
            })
            .collect::<Vec<_>>();

        if icall.ip() == DEBUGGING_IP {
            println!(
                "Relevant instruction count: {}",
                relevant_instructions.len()
            );

            for instr in &relevant_instructions {
                println!("{}", instr);
            }
        }

        // to consider this call as cfi-checked, we require the following:
        // we must perform a compare
        let mut cmp_found = false;

        // immediately following, we should have a jump to a ud1 or the call
        let mut ud1_jump_found = false;
        let mut call_jump_found = false;

        // if we have a jump to ud1, we know that we have a fallthrough to the call (since that is our icall instruction)
        // otherwise, we must assert that we have a ud1 fallthrough
        let mut ud1_fallthrough_found = false;

        // order: looking for cmp -> looking for jump -> looking for fallthrough

        // we now iterate over the relevant instructions to find the two branches
        // reverse to get back to original order
        relevant_instructions.iter().rev().for_each(|instruction| {
            // this may be made much stricter
            if instruction.mnemonic() == Mnemonic::Cmp {
                cmp_found = true;
            }

            // compare found, look for jump immediately following
            if cmp_found && !ud1_jump_found && !call_jump_found {
                // if actual jump instruction is found, follow it
                if instruction.is_jcc_short_or_near() {
                    if icall.ip() == DEBUGGING_IP {
                        println!("JMP found");
                        println!("Branch target: {}", instruction.near_branch_target());
                        println!("icall target: {}", icall.ip());
                    }
                    // look up the branch target in the address map
                    let Some(branch_target_index) =
                        self.address_map.get(&instruction.near_branch_target())
                    else {
                        if icall.ip() == DEBUGGING_IP {
                            println!("Branch target not found in address map")
                        }
                        return;
                    };

                    // get the branch target instruction
                    let Some(branch_target) = self.instructions.get(*branch_target_index) else {
                        if icall.ip() == DEBUGGING_IP {
                            println!("Branch instruction not found in instr vec")
                        }
                        return;
                    };

                    // check if the branch target is a ud1
                    if branch_target.mnemonic() == Mnemonic::Ud1 {
                        ud1_jump_found = true;
                        return;
                    }

                    // if jumping directly to the call instruction, we have found the call branch
                    if branch_target.ip() == icall.ip() {
                        call_jump_found = true;
                        return;
                    }

                    // if not, we search for the call instruction within the next instructions
                    // ass arg preparing instructions might push the actual call a bit down

                    // get the iterator at this position
                    let mut instruction_iter = self.instructions.iter().skip(*branch_target_index);

                    for _ in 0..ARGUMENT_LOADING_INSTRUCTION_COUNT {
                        let next_instruction = instruction_iter.next().unwrap();
                        if next_instruction.ip() == icall.ip() {
                            call_jump_found = true;
                            return;
                        }
                    }

                    // if the jump was neither to a call or ud1, this is not CFI relevant. Keep looking
                    cmp_found = false;
                }
            }

            // if we have found the jump to the call, we look for the UD1 fallthrough
            if call_jump_found {
                match instruction.mnemonic() {
                    Mnemonic::Ud1 => ud1_fallthrough_found = true,
                    _ => (),
                }
            }
        });

        if icall.ip() == 0x28d3089 {
            println!("cmp found: {}", cmp_found);
            println!("call jmp found: {}", call_jump_found);
            println!("ud1 jmp found: {}", ud1_jump_found);
            println!("ud1 fallthrough found: {}", ud1_fallthrough_found);
        }

        // if we found the compare
        if cmp_found
            // and call jump & ud1 fallthrough
            && ((call_jump_found && ud1_fallthrough_found)
            // or ud1 jump & call fallthrough
            || (ud1_jump_found))
        {
            // we are fine
            return Ok(());
        }
        return Err(());
    }
}
