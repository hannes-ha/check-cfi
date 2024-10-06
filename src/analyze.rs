use std::collections::{HashMap, HashSet, VecDeque};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfo, InstructionInfoFactory,
    Mnemonic, OpAccess, OpKind, Register,
};

use crate::{
    cfg::{CallPath, Cfg},
    io,
};

const DEBUGGING_IP: u64 = 0;

#[allow(dead_code)]
pub struct Analyzer {
    backtrack_limit: Option<usize>,
    instructions: Vec<Instruction>,
    icalls: Vec<Instruction>,
    address_map: HashMap<u64, usize>,
    jump_map: HashMap<u64, Vec<Instruction>>,
    checked: Vec<Instruction>,
    unchecked: Vec<(Instruction, String)>,
    safe_calls: HashMap<u64, Register>,
    function_borders: HashSet<u64>,
}

impl Analyzer {
    pub fn new(backtrack_limit: Option<usize>) -> Self {
        Analyzer {
            backtrack_limit,
            instructions: Vec::new(),
            icalls: Vec::new(),
            address_map: HashMap::new(),
            jump_map: HashMap::new(),
            checked: Vec::new(),
            unchecked: Vec::new(),
            safe_calls: HashMap::new(),
            function_borders: HashSet::new(),
        }
    }

    pub fn get_instruction_info(&self, ip: u64) -> Result<InstructionInfo, String> {
        let instruction = self.get_instruction(ip)?;
        Ok(InstructionInfoFactory::new().info(&instruction).clone())
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

    pub fn get_written_registers(&self, ip: u64) -> Result<Vec<Register>, String> {
        let written_regs = self
            .get_instruction_info(ip)?
            .used_registers()
            .iter()
            .filter(|register_use| match register_use.access() {
                OpAccess::Write
                | OpAccess::CondWrite
                | OpAccess::ReadWrite
                | OpAccess::ReadCondWrite => true,
                _ => false,
            })
            .map(|register_write_use| register_write_use.register())
            .collect::<Vec<Register>>();
        Ok(written_regs)
    }

    pub fn get_read_registers(&self, ip: u64) -> Result<Vec<Register>, String> {
        let read_regs = self
            .get_instruction_info(ip)?
            .used_registers()
            .iter()
            .filter(|register_use| match register_use.access() {
                OpAccess::Read => true,
                _ => false,
            })
            .map(|register_read_use| register_read_use.register())
            .collect::<Vec<_>>();
        Ok(read_regs)
    }

    pub fn disassemble(&mut self, code: &[u8], code_seg_offset: u64) {
        let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
        decoder.set_ip(code_seg_offset);

        let progress = io::progress_bar(code.len() as u64, "Disassembling");

        let mut instruction_index = 0;
        for instruction in decoder.iter() {
            self.instructions.push(instruction);
            self.address_map.insert(instruction.ip(), instruction_index);

            let flow_control = instruction.flow_control();

            if flow_control == FlowControl::IndirectCall
            // || flow_control == FlowControl::IndirectBranch
            {
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
                    self.jump_map
                        .entry(jump_target)
                        .or_insert(Vec::new())
                        .push(instruction);
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
        let progress = io::progress_bar(self.icalls.len() as u64, "Analyzing");
        for icall in self.icalls.iter() {
            match self.is_cfi_checked(icall) {
                Ok(_) => {
                    self.safe_calls
                        .insert(icall.ip(), get_register_or_mem_base(icall, 0));
                    self.checked.push(icall.clone()); // TODO: remove
                }
                Err(msg) => self.unchecked.push((icall.clone(), msg.to_string())),
            };
            progress.inc(1);
        }
        progress.finish();
    }

    pub fn get_results(&self) -> (&Vec<Instruction>, &Vec<(Instruction, String)>) {
        (&self.checked, &self.unchecked)
    }

    fn is_cfi_checked(&self, icall: &Instruction) -> Result<(), String> {
        let cfg = self.generate_cfg(icall.ip())?;

        if cfg.graph.node_count() > 1500 {
            eprintln!(
                "0x{:x} has high node count {}",
                icall.ip(),
                cfg.graph.node_count()
            )
        }
        if icall.ip() == DEBUGGING_IP {
            eprintln!(
                "edges:\n{}",
                cfg.graph
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
                cfg.call_paths
                    .iter()
                    .map(|cp| format!("0x{:x}", cp.entrypoint))
                    .collect::<Vec<_>>()
            );
        }

        // if no entrypoints, fail.
        if cfg.call_paths.len() == 0 {
            return Err("No entrypoints found".to_string());
        }

        // if we did not find the compare, fail
        if !cfg.cmp_found() {
            return Err("Compare not found".to_string());
        }

        // assert that the register used is one of the trusted ones
        cfg.assert_icall_to_trusted_register(&self)?;

        Ok(())
    }

    pub fn generate_cfg(&self, ip: u64) -> Result<Cfg, String> {
        let icall_instruction = self.get_instruction(ip)?;
        let mut cfg = Cfg::new(icall_instruction.clone());

        // insert the icall
        let icall_target = get_register_or_mem_base(&icall_instruction, 0);

        cfg.add_node(ip);

        // track set of trusted registers to limit search backwards
        let mut queue = VecDeque::<(u64, HashSet<Register>, u64)>::new();
        queue.push_back((ip, HashSet::default(), 0));

        while !queue.is_empty() {
            let Some((node_ip, mut trusted_registers, mut cmp_ip)) = queue.pop_front() else {
                break;
            };

            let instruction = self.get_instruction(node_ip)?;
            let parents = self.get_parents(node_ip)?;
            let mnemonic = instruction.mnemonic();

            // Stop at function border
            if self.function_borders.contains(&instruction.ip()) {
                cfg.call_paths
                    .push(CallPath::new(node_ip, trusted_registers, cmp_ip));
                continue;
            }

            // trusted registers evolve from a cmp leading to a ud1
            if mnemonic == Mnemonic::Cmp {
                Analyzer::debug(ip, "found cmp".to_string());

                let mut stack = self.get_children(&instruction)?;
                let mut visited = HashSet::new();
                while let Some(cmp_child) = stack.pop() {
                    visited.insert(cmp_child.ip());
                    if cmp_child.mnemonic() == Mnemonic::Ud1 {
                        // the registers involved in the compare are now considered trusted
                        trusted_registers.insert(instruction.op0_register());
                        cmp_ip = instruction.ip();
                        Analyzer::debug(ip, format!("Trusting {:?}", instruction.op0_register()));

                        match instruction.op1_kind() {
                            OpKind::Register => {
                                Analyzer::debug(
                                    ip,
                                    format!("Trusting {:?}", instruction.op1_register()),
                                );
                                trusted_registers.insert(instruction.op1_register());
                            }
                            _ => (),
                        }
                        continue;
                    }

                    // follow jumps. might be jmp -> jmp -> ud1
                    // do not follow nodes not on path unless jumps
                    if cmp_child.is_jmp_short_or_near()
                        || cmp_child.is_jcc_short_or_near()
                        || cfg.graph.contains_node(cmp_child.ip())
                    {
                        self.get_children(&cmp_child)?.iter().for_each(|gc| {
                            if !visited.contains(&gc.ip()) {
                                stack.push(*gc)
                            }
                        });
                    }
                }
            }

            // moving into registers propagate trust
            if mnemonic == Mnemonic::Mov {
                if trusted_registers.contains(&instruction.op0_register()) {
                    trusted_registers.insert(instruction.op1_register());
                    if instruction.op1_kind() == OpKind::Register {
                        trusted_registers.remove(&instruction.op0_register());
                    }
                }
            }

            // if the call register is trusted, we can stop looking at this leg
            if trusted_registers.contains(&icall_target) {
                cfg.call_paths
                    .push(CallPath::new(node_ip, trusted_registers, cmp_ip));
                continue;
            }

            for parent in parents {
                let parent_ip = parent.ip();
                // add node if it doesnt already exist
                if !cfg.contains_node(parent_ip) {
                    cfg.add_node(parent_ip);
                    // we dont need to visit parents more than once
                    queue.push_back((parent_ip, trusted_registers.clone(), cmp_ip));
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
            _ => (),
        }
        Ok(jump_prevs)
    }

    fn get_children(&self, instruction: &Instruction) -> Result<Vec<Instruction>, String> {
        let index = self.get_instruction_index(instruction.ip())?;
        let chronological_next = self.get_instruction_from_index(index + 1)?;

        match instruction.flow_control() {
            // one child (next)
            FlowControl::Next | FlowControl::Call | FlowControl::XbeginXabortXend => {
                Ok(vec![chronological_next])
            }

            // one child (jmp target)
            FlowControl::UnconditionalBranch => {
                let branch_target = self.get_instruction(instruction.near_branch_target())?;
                Ok(vec![branch_target])
            }

            // twho chilren, next and jump target
            FlowControl::ConditionalBranch => {
                let branch_target = self.get_instruction(instruction.near_branch_target())?;
                Ok(vec![branch_target, chronological_next])
            }

            // one child, undecideable
            FlowControl::IndirectCall | FlowControl::IndirectBranch |
            // no children
            FlowControl::Interrupt | FlowControl::Return | FlowControl::Exception => Ok(Vec::new()),
        }
    }
}

pub fn get_register_or_mem_base(instruction: &Instruction, position: u32) -> Register {
    match instruction.op_kind(position) {
        OpKind::Register => instruction.op_register(position),
        OpKind::Memory => instruction.memory_base(),
        unknown => unimplemented!("unknown opkind {:?}", unknown),
    }
}
