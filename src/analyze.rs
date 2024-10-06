use std::collections::VecDeque;

use colored::Colorize;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind};

const INSTRUCTION_BUFFER_SIZE: usize = 15;

/*
    A call instruction is considered "cfi-checked" if:
        - the value has ben compared (cmp) with another, static value.
        - the result of the comparison result in a branch to the call instruction OR to a ud1 instruction

            caviats:
        - the branch to the call instruction does not need to be direct, often it will point to instructions loading arguments.
             but no modifications to the call target should be made before the actual call
        - the comparison can be made on another register, holding the same value (ignore?)
*/

fn is_cfi_checked_2(icall: &Instruction, predecessors: &VecDeque<Instruction>) -> Result<(), ()> {
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
    let instr = relevant_inst.pop_back().ok_or(())?;
    match instr.mnemonic() {
        Mnemonic::Jbe | Mnemonic::Je => {
            jmp_target = instr.memory_displacement64();
        }
        _ => return Err(()),
    }

    // next instruction should be ud1
    let instr = relevant_inst.pop_back().ok_or(())?;
    if instr.mnemonic() != Mnemonic::Ud1 {
        return Err(());
    }

    // now, the jump target should be passed
    // and the target register should not be touched

    let mut jump_target_passed = Err(());
    while let Some(instr) = relevant_inst.pop_back() {
        if instr.ip() == jmp_target {
            jump_target_passed = Ok(())
        }

        // this might be unnessecary/overkill
        match icall.op0_kind() {
            OpKind::Register => {
                if instr.op0_register() == icall.op0_register() {
                    return Err(());
                }
            }
            OpKind::Memory => {
                if instr.memory_displacement64() == icall.memory_displacement64() {
                    return Err(());
                }
            }
            _ => {}
        }
    }

    jump_target_passed
}
pub fn disassembled_iced(code: &[u8], offset: u64) {
    // set up iced
    let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
    decoder.set_ip(offset);

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
                if is_cfi_checked_2(&instruction, &predecessors).is_ok() {
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
