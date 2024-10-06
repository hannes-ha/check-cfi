use std::collections::VecDeque;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use indicatif::ProgressStyle;

const INSTRUCTION_BUFFER_SIZE: usize = 15;

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

fn is_cfi_checked_2(icall: &Instruction, predecessors: &VecDeque<Instruction>) -> Result<(), ()> {
    // only keep instructions since last cmp
    let mut relevant_inst: VecDeque<_> = predecessors
        .iter()
        .rev()
        .take_while(|instr| instr.mnemonic() != Mnemonic::Cmp)
        .collect();

    // if we did not find a cmp, fail
    if relevant_inst.len() == predecessors.len() {
        return Err(());
    }



    // the instruction after the cmp should be a jump
    let jmp_target: u64;
    let instr = relevant_inst.pop_back().ok_or(())?;
    match instr.mnemonic() {
        Mnemonic::Jbe | Mnemonic::Je | Mnemonic::Ja => {
            jmp_target = instr.memory_displacement64();
        }
        _ => return Err(()),
    }

    // next instruction should be ud1
    // TODO: allow jmp to ud1
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
                // clang sometimes emit a mov rax rax wich is a no-op
                if instr.op0_register() == icall.op0_register()
                    && instr.op1_register() != icall.op1_register()
                {
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
    // if no args is passed to the call, the jump target may be the call instruction
    if icall.ip() == jmp_target {
        jump_target_passed = Ok(());
        
    }

    jump_target_passed
}


pub fn disassembled_iced(
    code: &[u8],
    offset: u64,
    limit_unchecked: usize,
) -> (Vec<Instruction>, Vec<Instruction>) {
    eprint!("Dissasembling...");
    let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
    decoder.set_ip(offset);
    eprintln!("done.");

    let mut checked = Vec::<Instruction>::new();
    let mut unchecked = Vec::<Instruction>::new();

    let mut predecessors = VecDeque::<Instruction>::new();

    let progress = indicatif::ProgressBar::new(code.len() as u64);
    progress.set_style(
        ProgressStyle::with_template("Analyzing: [{bar} {percent}%]")
            .unwrap()
            .progress_chars("=>-"),
    );

    for instruction in decoder.iter() {
        // find indirect calls
        if instruction.is_call_far_indirect() || instruction.is_call_near_indirect() {
            // if its relative to RIP or EIP, its fine (RIGHT?!)
            // we somehow need to remove the "indirect" calls to __cxa_finalize
            // are these simply DSOs?
            if !instruction.is_ip_rel_memory_operand() {
                if is_cfi_checked_2(&instruction, &predecessors).is_ok() {
                    checked.push(instruction);
                } else {
                    unchecked.push(instruction);
                    if limit_unchecked > 0 && unchecked.len() >= limit_unchecked {
                        break;
                    }
                }
                predecessors.clear();
            }
        }
        predecessors.push_back(instruction);

        // if length is above buffer size, pop the oldest
        if predecessors.len() > INSTRUCTION_BUFFER_SIZE {
            predecessors.pop_front();
        }
        progress.inc(instruction.len() as u64);
    }
    progress.finish();
    return (checked, unchecked);
}
