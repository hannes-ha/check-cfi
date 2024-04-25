#[allow(dead_code)]
fn is_cfi_checked(&self, icall: &Instruction) -> Result<(), &str> {
    // look up the instructions index in the vector
    let Some(instruction_index) = self.address_map.get(&icall.ip()) else {
        return Err("Instruction not found in vector");
    };

    // predecessor index is instruction_index - 15 (minimum 0)
    let predecessor_index = if *instruction_index > INSTRUCTION_BUFFER_SIZE {
        *instruction_index - INSTRUCTION_BUFFER_SIZE
    } else {
        0
    };

    // get predecessors by slicing 15 instructions from the instruction vector
    let Some(predecessors) = self.instructions.get(predecessor_index..*instruction_index) else {
        return Err("Could not get predecessors");
    };

    // save the predecessors up until the value of the call target is loaded
    let relevant_instructions = predecessors
        .iter()
        .rev()
        .take_while(|instruction| {
            match instruction.mnemonic() {
                // stop if we run in to another call and we are using RAX for our call
                Mnemonic::Call => match icall.op0_kind() {
                    OpKind::Register => return icall.op0_register() != Register::RAX,
                    OpKind::Memory => return icall.memory_base() != Register::RAX,
                    unknown => unimplemented!("OpKind: {:?} not implemented", unknown),
                },
                // stop where the call target is loaded
                Mnemonic::Mov => match icall.op0_kind() {
                    OpKind::Register => return instruction.op0_register() != icall.op0_register(),
                    OpKind::Memory => !(is_mem_op_matching(instruction, icall)),
                    unknown => unimplemented!("OpKind: {:?} not implemented", unknown),
                },
                _ => return true,
            }
        })
        .collect::<Vec<_>>();

    // if we did not find the instruction loading the call target, we cannot determine if this is cfi-checked
    if relevant_instructions.len() == predecessors.len() {
        return Err("Could not find instruction loading jump target");
    }

    if icall.ip() == DEBUGGING_IP {
        eprintln!(
            "Relevant instruction count: {}",
            relevant_instructions.len()
        );

        for instr in &relevant_instructions {
            eprintln!("{}", instr);
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

    // friends are registers that are considered relevant to the call target
    // this is to avoid looking at completely irrelevant cmps, i.e. cmp rdi,r10 is not relevant if we are calling rax
    // unless we have recently moved the value from rax to rdi
    let mut friends = Vec::new();

    let icall_target = match icall.op0_kind() {
        OpKind::Register => icall.op0_register(),
        OpKind::Memory => icall.memory_base(),
        op => unimplemented!("OpKind: {:?} not implemented", op),
    };

    friends.push(icall_target);

    // we now iterate over the relevant instructions to find the two branches
    // reverse to get back to original order
    relevant_instructions.iter().rev().for_each(|instruction| {
        if instruction.mnemonic() == Mnemonic::Cmp {
            // if one of the compared operands is one of our friends, we have found the compare
            let left = match instruction.op0_kind() {
                OpKind::Register => instruction.op0_register(),
                OpKind::Memory => instruction.memory_base(),
                _ => Register::None,
            };

            let right = match instruction.op1_kind() {
                OpKind::Register => instruction.op1_register(),
                OpKind::Memory => instruction.memory_base(),
                _ => Register::None,
            };

            if friends.contains(&left) || friends.contains(&right) {
                cmp_found = true;
            }
        }

        if instruction.mnemonic() == Mnemonic::Mov {
            let move_from = match instruction.op1_kind() {
                OpKind::Register => Ok(instruction.op1_register()),
                OpKind::Memory => Ok(instruction.memory_base()),
                _ => Err(()),
            };

            if move_from.is_ok() && friends.contains(&move_from.unwrap()) {
                // if we move from a friend to another register, we consider this register a friend as well
                let move_to = match instruction.op0_kind() {
                    OpKind::Register => instruction.op0_register(),
                    OpKind::Memory => instruction.memory_base(),
                    _ => unimplemented!("OpKind: {:?} not implemented", instruction.op0_kind()),
                };

                friends.push(move_to);
            }
        }

        // compare found, look for jump immediately following
        if cmp_found && !ud1_jump_found && !call_jump_found {
            // if actual jump instruction is found, follow it
            if instruction.is_jcc_short_or_near() {
                if icall.ip() == DEBUGGING_IP {
                    eprintln!("JMP found");
                    eprintln!("Branch target: {}", instruction.near_branch_target());
                    eprintln!("icall ip: {}", icall.ip());
                }
                // look up the branch target in the address map
                let Some(branch_target_index) =
                    self.address_map.get(&instruction.near_branch_target())
                else {
                    if icall.ip() == DEBUGGING_IP {
                        eprintln!("Branch target not found in address map")
                    }
                    return;
                };

                // get the branch target instruction
                let Some(branch_target) = self.instructions.get(*branch_target_index) else {
                    if icall.ip() == DEBUGGING_IP {
                        eprintln!("Branch instruction not found in instr vec")
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
                    match instruction_iter.next() {
                        Some(next_instruction) => {
                            if next_instruction.ip() == icall.ip() {
                                call_jump_found = true;
                                return;
                            }
                        }
                        _ => return,
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

    if icall.ip() == DEBUGGING_IP {
        eprintln!("cmp found: {}", cmp_found);
        eprintln!("call jmp found: {}", call_jump_found);
        eprintln!("ud1 jmp found: {}", ud1_jump_found);
        eprintln!("ud1 fallthrough found: {}", ud1_fallthrough_found);
    }

    // if we found the compare
    if cmp_found {
        // and call jump & ud1 fallthrough or ud1 jump & call fallthrough
        if (call_jump_found && ud1_fallthrough_found) || (ud1_jump_found) {
            // we are fine
            return Ok(());
        } else {
            return Err("Ud1 branch not found");
        }
    } else {
        return Err("Compare not found.");
    }
}

#[allow(dead_code)]
fn is_cfi_checked_2(&self, icall: &Instruction) -> Result<(), String> {
    let Some(icall_index) = self.address_map.get(&icall.ip()) else {
        return Err("Instruction not found in vector".to_string());
    };

    // let cfg = cfg::generate_cfg();

    let mut predecessor_index = icall_index - 1;

    let mut trusted = HashSet::<Register>::new();

    let call_target = get_register_or_mem_base(icall, 0);
    let mut ud1_found = false;
    let mut ud1_index = 0;

    // iterate the instructions, backwards
    // we want to indentify the ud1 or jump to ud1, and from that determine what registers are
    // trusted. Any register involved in a `cmp jmp ud1` sequence is considered trusted
    while predecessor_index > 0 {
        if (icall_index - predecessor_index) > BACKTRACK_LIMIT {
            return Err("Backtrack limit reached.".to_string());
        }
        if icall.ip() == DEBUGGING_IP {
            eprintln!("Checking predecessor at index {}", predecessor_index);
        }

        let Some(instruction) = self.instructions.get(predecessor_index) else {
            return Err("Backward search failed".to_string());
        };

        // if we have determined our call target as trusted, stop looking
        if trusted.contains(&call_target) {
            if icall.ip() == DEBUGGING_IP {
                eprintln!("Target trusted");
            }
            // we cannot return yet, because we have to make sure our trusted register are not
            // touched before the call
            break;
        }

        match instruction.mnemonic() {
            // if we find the top of a function, stop looking
            Mnemonic::Push => {
                if instruction.op0_register() == Register::RBP {
                    if icall.ip() == DEBUGGING_IP {
                        eprintln!("Breaking on function border.");
                    }
                    break;
                }
            }

            Mnemonic::Jae | Mnemonic::Ja | Mnemonic::Jne => {
                if !ud1_found {
                    // look up the branch target in the address map
                    let Some(jump_target_index) =
                        self.address_map.get(&instruction.near_branch_target())
                    else {
                        predecessor_index -= 1;
                        continue;
                    };

                    // get the branch target instruction
                    let Some(branch_target) = self.instructions.get(*jump_target_index) else {
                        predecessor_index -= 1;
                        continue;
                    };

                    // check if the branch target is a ud1
                    if branch_target.mnemonic() == Mnemonic::Ud1 {
                        if icall.ip() == DEBUGGING_IP {
                            eprintln!("Found jump to ud1");
                        }
                        ud1_found = true;
                        ud1_index = predecessor_index;

                        // on occation, there might be instructions placed between the jcc and
                        // cmp. These are ignored as long as they dont affect the control flow
                        let mut cmp: &Instruction;
                        loop {
                            predecessor_index -= 1;
                            let opt_cmp = self.instructions.get(predecessor_index);

                            match opt_cmp {
                                Some(instr) => cmp = instr,
                                None => {
                                    return Err(format!(
                                        "Failed to get instruction at index {}",
                                        predecessor_index
                                    ))
                                }
                            }

                            // compare found
                            if cmp.mnemonic() == Mnemonic::Cmp {
                                break;
                            }

                            // skip if not affecting control flow
                            if cmp.flow_control() != FlowControl::Next {
                                return Err("Something breaking control flow between jcc and cmp"
                                    .to_string());
                            }
                        }

                        // mark the compared registers as trusted
                        trusted.insert(cmp.op0_register());
                        if icall.ip() == DEBUGGING_IP {
                            eprintln!("Trusting {:?}", cmp.op0_register());
                        }
                        match cmp.op1_kind() {
                            OpKind::Register => {
                                if icall.ip() == DEBUGGING_IP {
                                    eprintln!("Trusting {:?}", cmp.op1_register());
                                }
                                trusted.insert(cmp.op1_register());
                            }
                            _ => (),
                        }
                    }
                }
            }
            Mnemonic::Ud1 => {
                if !ud1_found {
                    if icall.ip() == DEBUGGING_IP {
                        eprintln!("Found stray ud1");
                    }
                    // ud1 found. Now we may start marking registers as trusted
                    // before the ud1, there should be a conditional jump
                    ud1_index = predecessor_index;
                    predecessor_index -= 1;
                    let Some(jump) = self.instructions.get(predecessor_index) else {
                        return Err("Could not get jump predeceding the ud1".to_string());
                    };

                    if !jump.is_jcc_short_or_near() {
                        // TODO: resove route to call
                        return Err("long jump".to_string());
                    }
                    // before the conditional jump, there should be a compare
                    predecessor_index -= 1;
                    let Some(cmp) = self.instructions.get(predecessor_index) else {
                        return Err("Could not get cmp predeceding the ud1".to_string());
                    };

                    if cmp.mnemonic() != Mnemonic::Cmp {
                        return Err("Something other than a cmp preceeded the jcc, ud1".to_string());
                    }

                    // mark the compared registers as trusted
                    trusted.insert(cmp.op0_register());
                    if icall.ip() == DEBUGGING_IP {
                        eprintln!("Trusting {:?}", cmp.op0_register());
                    }
                    match cmp.op1_kind() {
                        OpKind::Register => {
                            if icall.ip() == DEBUGGING_IP {
                                eprintln!("Trusting {:?}", cmp.op1_register());
                            }
                            trusted.insert(cmp.op1_register());
                        }
                        _ => (),
                    }

                    // we can now propagate the trusted registers
                    ud1_found = true;
                }
            }

            Mnemonic::Mov | Mnemonic::Sub => {
                // if something is moved into a trusted register, that value is also trusted
                if ud1_found
                    && trusted.contains(&instruction.op0_register())
                    && instruction.op1_kind() == OpKind::Register
                {
                    trusted.insert(instruction.op1_register());
                    if icall.ip() == DEBUGGING_IP {
                        eprintln!("Trusting {:?}", instruction.op1_register());
                        eprintln!("Trusted is now {:?}", trusted);
                    }
                }
            }

            // TODO: ud1 jumps, calls (?) skip on way up? Or err?
            _ => (),
        }
        predecessor_index -= 1;
    }

    let iterated_instructions = icall_index - predecessor_index;

    // at the point of the ud1 compare, we now have a set of trusted registers.
    // if these are now overwritten, we do not consider them trusted anymore
    // we start iterating from the place where we found the ud1
    // now we must respect the CFG

    // TODO: CFG this
    for instruction in self.instructions.iter().skip(ud1_index) {
        if icall.ip() == DEBUGGING_IP {
            eprintln!("forward roll, instruction: 0x{:x}", instruction.ip());
        }
        // when we reach our icall, the search is complete
        if instruction.ip() == icall.ip() {
            break;
        }

        //  let info = self.info_factory.info(instruction);
        // let read_registers = info.used_registers();

        match instruction.mnemonic() {
            Mnemonic::Mov => {
                // if we move from a untrusted to a trusted register, that register is no longer
                // trusted
                if instruction.op1_kind() == OpKind::Register
                    || instruction.op1_kind() == OpKind::Memory
                {
                    let to = get_register_or_mem_base(instruction, 0);
                    let from = get_register_or_mem_base(instruction, 1);

                    // untrusted -> trusted, remove trusted
                    if trusted.contains(&to) && !trusted.contains(&from) {
                        trusted.remove(&to);
                        if icall.ip() == DEBUGGING_IP {
                            eprintln!("fwd: Untrusting {:?}", to);
                            eprintln!("Trusted is now {:?}", trusted);
                            eprintln!("instruction: 0x{:x}", instruction.ip());
                        }
                    }
                    // trusted -> untrusted, add trusted
                    if trusted.contains(&from) && !trusted.contains(&to) {
                        trusted.insert(to);
                        if icall.ip() == DEBUGGING_IP {
                            eprintln!("fwd: Trusting {:?}", from);
                            eprintln!("Trusted is now {:?}", trusted);
                            eprintln!("instruction: 0x{:x}", instruction.ip());
                        }
                    }
                }
            }
            // TODO: if we call a function, we now only trust callee-saved
            _ => (),
        }
    }

    if trusted.contains(&call_target) {
        Ok(())
    } else {
        if icall.ip() == DEBUGGING_IP {
            eprintln!(
                "Call target not trusted. Looked at {} instructions. Trusted registers: {:?}",
                iterated_instructions, trusted
            )
        }

        Err(format!(
            "Call target not trusted. Looked at {} instructions. Trusted registers: {:?}",
            iterated_instructions, trusted
        ))
    }
}
