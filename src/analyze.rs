use std::collections::{HashMap, HashSet, VecDeque};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpKind,
    Register,
};
use indicatif::ProgressStyle;
use petgraph::visit::Bfs;

use crate::cfg::Cfg;

const INSTRUCTION_BUFFER_SIZE: usize = 40;
const ARGUMENT_LOADING_INSTRUCTION_COUNT: usize = 20;
const DEBUGGING_IP: u64 = 0x5faed6;
const BACKTRACK_LIMIT: usize = 200;

#[allow(dead_code)]
pub struct Analyzer {
    instructions: Vec<Instruction>,
    icalls: Vec<Instruction>,
    address_map: HashMap<u64, usize>,
    jump_map: HashMap<u64, Vec<Instruction>>,
    checked: Vec<Instruction>,
    unchecked: Vec<(Instruction, String)>,
    info_factory: InstructionInfoFactory,
    safe_calls: HashMap<u64, Register>,
    function_borders: HashSet<u64>,
}

impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            instructions: Vec::new(),
            icalls: Vec::new(),
            address_map: HashMap::new(),
            jump_map: HashMap::new(),
            checked: Vec::new(),
            unchecked: Vec::new(),
            info_factory: InstructionInfoFactory::new(),
            safe_calls: HashMap::new(),
            function_borders: HashSet::new(),
        }
    }

    pub fn debug(ip: u64, msg: String) {
        if ip == DEBUGGING_IP {
            eprintln!("{}", msg)
        }
    }

    pub fn get_jumps_to(&self, ip: u64) -> Vec<Instruction> {
        match self.jump_map.get(&ip) {
            Some(instructions) => instructions.to_vec(),
            None => Vec::<Instruction>::default(),
        }
    }

    pub fn get_instruction_index(&self, ip: u64) -> Result<usize, String> {
        match self.address_map.get(&ip) {
            Some(&index) => Ok(index),
            None => Err(format!("Instruction at 0x{:x} not found", ip)),
        }
    }

    pub fn get_instruction_from_index(&self, index: usize) -> Result<Instruction, String> {
        match self.instructions.get(index) {
            Some(&instruction) => Ok(instruction),
            None => Err(format!("Instruction at index {} not found", index)),
        }
    }

    pub fn get_instruction(&self, ip: u64) -> Result<Instruction, String> {
        let index = self.get_instruction_index(ip)?;
        self.get_instruction_from_index(index)
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

        let mut instruction_index = 0;
        for instruction in decoder.iter() {
            self.instructions.push(instruction);
            self.address_map.insert(instruction.ip(), instruction_index);

            let flow_control = instruction.flow_control();

            // collect icalls
            if
            /*flow_control == FlowControl::IndirectBranch*/
            flow_control == FlowControl::IndirectCall {
                if !instruction.is_ip_rel_memory_operand() {
                    self.icalls.push(instruction);
                }
            }

            // track close jumps to be able to construct cfg later
            if instruction.is_jmp_short_or_near() || instruction.is_jcc_short_or_near() {
                // jump target is map key
                let jump_target = instruction.near_branch_target();
                // we only care about near branches
                if jump_target > 0 {
                    let prev_targets = self.jump_map.entry(jump_target).or_insert(Vec::new());
                    prev_targets.push(instruction);
                }
            }

            // use call targets to track function borders
            if flow_control == FlowControl::Call {
                if !instruction.is_ip_rel_memory_operand() {
                    self.function_borders
                        .insert(instruction.memory_displacement64());
                }
            }

            instruction_index += 1;
            progress.inc(instruction.len() as u64);
        }

        progress.finish();
    }

    pub fn analyze(&mut self) {
        let progress = indicatif::ProgressBar::new(self.icalls.len() as u64);
        progress.set_style(
            ProgressStyle::with_template("Analyzing:     [{bar} {percent}%]")
                .unwrap()
                .progress_chars("=>-"),
        );

        for icall in self.icalls.iter() {
            match self.is_cfi_checked_3(icall) {
                Ok(_) => {
                    self.safe_calls
                        .insert(icall.ip(), get_register_or_mem_base(icall, 0));
                    self.checked.push(icall.clone());
                }
                Err(msg) => self.unchecked.push((icall.clone(), msg)),
            };
            progress.inc(1);
        }
        progress.finish();
    }

    pub fn get_results(&self) -> (&Vec<Instruction>, &Vec<(Instruction, String)>) {
        (&self.checked, &self.unchecked)
    }

    fn is_cfi_checked_3(&self, icall: &Instruction) -> Result<(), String> {
        let cfg = self.generate_cfg(icall.ip())?;

        if cfg.fwd_graph.node_count() > 10000 {
            eprintln!(
                "0x{:x} has high node count {}",
                icall.ip(),
                cfg.fwd_graph.node_count()
            )
        }
        if icall.ip() == DEBUGGING_IP {
            eprintln!(
                "edges:\n{}",
                cfg.fwd_graph
                    .all_edges()
                    .map(|e| {
                        let (from, to, _) = e;
                        return format!("0x{:x} -> 0x{:x}", from, to);
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            eprintln!(
                "entry: {:?}",
                cfg.entrypoints
                    .iter()
                    .map(|e| format!("0x{:x}", e))
                    .collect::<Vec<_>>()
            );
        }

        // we now iterate the graph from the entrypoint asserting 3 properties
        // 1. the branch must pass through a ud1 or a cmp jcc ud1
        // 2. the called register must be a trusted register
        // 3. the called register may not be touched between the compare and the call
        // find_compare(&graph, entrypoint) -> Instruction
        // assert_is_trusted(&graph, icall, cmp_instruction) -> bool
        // assert_untouched(&graph, cmp_instruction) -> bool
        //
        // running only ud1 check gives 191 "misses" wich is probably what to aim for.
        // if no entrypoints, fail.
        if cfg.entrypoints.len() == 0 {
            return Err("No entrypoints found".to_string());
        }

        // for entrypoint in &cfg.entrypoints {
        let _cmp_ip = cfg.find_compare(&self, icall.ip())?;
        // }
        Ok(())
    }

    pub fn generate_cfg(&self, ip: u64) -> Result<Cfg, String> {
        let mut cfg = Cfg::new();

        // insert the icall
        let icall_instruction = self.get_instruction(ip)?;
        cfg.add_node(ip);
        let icall_target = get_register_or_mem_base(&icall_instruction, 0);

        let mut queue = VecDeque::<(u64, HashSet<Register>)>::new();
        queue.push_back((ip, HashSet::default()));

        while !queue.is_empty() {
            let Some((node_ip, mut trusted_registers)) = queue.pop_front() else {
                break;
            };

            let instruction = self.get_instruction(node_ip)?;
            let parents = self.get_parents(node_ip)?;
            let mnemonic = instruction.mnemonic();

            // Stop at function border
            if self.function_borders.contains(&instruction.ip()) {
                cfg.entrypoints.push(node_ip);
                continue;
            }

            // safe registers may come from two sources,
            // either through a compare and jump to a ud1
            if mnemonic == Mnemonic::Cmp {
                Analyzer::debug(icall_instruction.ip(), "found cmp".to_string());
                // check the cfg if this cmp leads to a ud1
                let mut bfs = Bfs::new(&cfg.fwd_graph, node_ip);
                while let Some(ip) = bfs.next(&cfg.fwd_graph) {
                    let cmp_child = self.get_instruction(ip)?;
                    Analyzer::debug(
                        icall_instruction.ip(),
                        format!("looking at child 0x{:x}", cmp_child.ip()),
                    );
                    if cmp_child.mnemonic() == Mnemonic::Ud1 {
                        // the registers involved in the compare are now considered trusted
                        trusted_registers.insert(instruction.op0_register());
                        if icall_instruction.ip() == DEBUGGING_IP {
                            eprintln!("Trusting {:?}", instruction.op0_register());
                        }
                        match instruction.op1_kind() {
                            OpKind::Register => {
                                if icall_instruction.ip() == DEBUGGING_IP {
                                    eprintln!("Trusting {:?}", instruction.op1_register());
                                }
                                trusted_registers.insert(instruction.op1_register());
                            }
                            _ => (),
                        }
                    }

                    if cmp_child.mnemonic() == Mnemonic::Jne
                        || cmp_child.mnemonic() == Mnemonic::Je
                        || cmp_child.mnemonic() == Mnemonic::Jae
                    {
                        Self::debug(node_ip, "found a jump".to_string());
                        let Some(jump_target_index) =
                            self.address_map.get(&cmp_child.near_branch_target())
                        else {
                            continue;
                        };

                        // get the branch target instruction
                        let Some(branch_target) = self.instructions.get(*jump_target_index) else {
                            continue;
                        };

                        // check if the branch target is a ud1
                        // TODO fix duplication
                        if branch_target.mnemonic() == Mnemonic::Ud1 {
                            trusted_registers.insert(instruction.op0_register());
                            if icall_instruction.ip() == DEBUGGING_IP {
                                eprintln!("Trusting {:?}", instruction.op0_register());
                            }
                            match instruction.op1_kind() {
                                OpKind::Register => {
                                    if icall_instruction.ip() == DEBUGGING_IP {
                                        eprintln!("Trusting {:?}", instruction.op1_register());
                                    }
                                    trusted_registers.insert(instruction.op1_register());
                                }
                                _ => (),
                            }
                        }
                    }
                }
            }
            // ...or through a previously determined safe register
            // needs love
            // if instruction.is_call_far_indirect() || instruction.is_call_near_indirect() {
            //     let Some(trusted_reg) = self.safe_calls.get(&instruction.ip()) else {}
            //     trusted_registers.insert(trusted_reg);
            // }
            //
            // moving into registers propagate trust
            // TODO might need sub here
            if mnemonic == Mnemonic::Mov {
                if trusted_registers.contains(&instruction.op0_register())
                    && instruction.op1_kind() == OpKind::Register
                {
                    trusted_registers.insert(instruction.op1_register());
                    trusted_registers.remove(&instruction.op0_register());
                    if instruction.ip() == DEBUGGING_IP {
                        eprintln!("Trusting {:?}", instruction.op1_register());
                        eprintln!("Untrusting {:?}", instruction.op0_register());
                        eprintln!("Trusted is now {:?}", trusted_registers);
                    }
                }
            }

            // if the call register is trusted, we can stop looking at this leg
            if trusted_registers.contains(&icall_target) {
                cfg.entrypoints.push(node_ip);
                continue;
            }

            for parent in parents {
                let parent_ip = parent.ip();
                // add node if it doesnt already exist
                if !cfg.contains_node(parent_ip) {
                    cfg.add_node(parent_ip);
                    // we dont need to visit parents more than once
                    queue.push_back((parent_ip, trusted_registers.clone()));
                }
                // else just add edge
                cfg.add_edge(parent_ip, node_ip);
            }
        }

        Ok(cfg)
    }

    fn get_parents(&self, ip: u64) -> Result<Vec<Instruction>, String> {
        let index = self.get_instruction_index(ip)?;
        let chronological_prev = self.get_instruction_from_index(index - 1)?;
        let mut jump_prevs = self.get_jumps_to(ip);
        // check if chronological prev is really a parent
        match chronological_prev.flow_control() {
            FlowControl::Call
            | FlowControl::Next
            | FlowControl::ConditionalBranch
            | FlowControl::IndirectCall => jump_prevs.push(chronological_prev),
            _ => {
                if DEBUGGING_IP.abs_diff(ip) < 200 {
                    eprintln!("stopping on 0x{:x}", ip)
                }
            }
        }
        Ok(jump_prevs)
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
                                    return Err(
                                        "Something breaking control flow between jcc and cmp"
                                            .to_string(),
                                    );
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
                            return Err(
                                "Something other than a cmp preceeded the jcc, ud1".to_string()
                            );
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
        let Some(predecessors) = self.instructions.get(predecessor_index..*instruction_index)
        else {
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
                        OpKind::Register => {
                            return instruction.op0_register() != icall.op0_register()
                        }
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
}

pub fn is_mem_op_matching(ins_a: &Instruction, ins_b: &Instruction) -> bool {
    // check if the memory operand is the same
    return ins_a.memory_displacement64() == ins_b.memory_displacement64()
        && ins_a.memory_base() == ins_b.memory_base()
        && ins_a.memory_index() == ins_b.memory_index()
        && ins_a.memory_index_scale() == ins_b.memory_index_scale();
}

pub fn get_register_or_mem_base(instruction: &Instruction, position: u32) -> Register {
    match instruction.op_kind(position) {
        OpKind::Register => instruction.op_register(position),
        OpKind::Memory => instruction.memory_base(),
        unknown => unimplemented!("unknown opkind {:?}", unknown),
    }
}
