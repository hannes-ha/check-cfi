use std::collections::{HashMap, HashSet};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfo, InstructionInfoFactory,
    OpAccess, OpKind, Register,
};

use crate::{cfg::Cfg, io};

const DEBUGGING_IP: u64 = 0xb4d02c;

#[allow(dead_code)]
pub struct Analyzer {
    backtrack_limit: Option<usize>,
    enable_jumps: bool,
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
    pub fn new(backtrack_limit: Option<usize>, enable_jumps: bool) -> Self {
        Analyzer {
            backtrack_limit,
            enable_jumps,
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

    pub fn is_function_border(&self, ip: &u64) -> bool {
        return self.function_borders.contains(ip);
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

    pub fn disassemble(
        &mut self,
        code: &[u8],
        code_seg_offset: u64,
        symbol_map: &mut HashMap<u64, String>,
    ) {
        let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
        decoder.set_ip(code_seg_offset);

        let progress = io::progress_bar(code.len() as u64, "Disassembling");

        let mut current_symbol = "".to_string();

        let mut instruction_index = 0;
        for instruction in decoder.iter() {
            current_symbol = match symbol_map.get(&instruction.ip()) {
                Some(new_sym) => new_sym.to_string(),
                _ => current_symbol,
            };
            self.instructions.push(instruction);
            self.address_map.insert(instruction.ip(), instruction_index);

            let flow_control = instruction.flow_control();

            if flow_control == FlowControl::IndirectCall
                || (self.enable_jumps && flow_control == FlowControl::IndirectBranch)
            {
                self.icalls.push(instruction);
                symbol_map.insert(instruction.ip(), current_symbol.clone());
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
                    Self::debug(icall.ip(), "Trusted".to_string());
                    self.safe_calls
                        .insert(icall.ip(), get_register_or_mem_base(icall, 0));
                    self.checked.push(icall.clone()); // TODO: remove
                }
                Err(msg) => {
                    Self::debug(icall.ip(), format!("NOT trusted: {}", msg));
                    self.unchecked.push((icall.clone(), msg.to_string()))
                }
            };
            progress.inc(1);
        }
        progress.finish();
    }

    pub fn get_results(&self) -> (&Vec<Instruction>, &Vec<(Instruction, String)>) {
        (&self.checked, &self.unchecked)
    }

    fn is_cfi_checked(&self, icall: &Instruction) -> Result<(), String> {
        // if the call target is stored on the stack, assume untrusted
        if is_stack_relative(icall, 0) {
            return Err("Call target spilled to stack".to_string());
        }

        let cfg = Cfg::new(*icall, self)?;

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
                        return format!(
                            "0x{:x} -> 0x{:x}. Instruction: {:?}",
                            from,
                            to,
                            self.get_instruction(from).unwrap().mnemonic()
                        );
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

    pub fn get_parents(&self, ip: u64) -> Result<Vec<Instruction>, String> {
        let index = self.get_instruction_index(ip)?;
        let mut jump_prevs = self.get_jumps_to(ip);

        if index > 1 {
            let chronological_prev = self.get_instruction_from_index(index - 1)?;

            // check if chronological prev is really a parent
            match chronological_prev.flow_control() {
            FlowControl::Call
            | FlowControl::Next
            | FlowControl::ConditionalBranch
             // | FlowControl::Return // we want to discover function borders in the cfg, so keep returns as
                // a parent for now
            | FlowControl::IndirectCall => jump_prevs.push(chronological_prev),
            _ => (),
        }
        }
        Ok(jump_prevs)
    }

    pub fn get_children(&self, ip: u64) -> Result<Vec<Instruction>, String> {
        let instruction = self.get_instruction(ip)?;
        let index = self.get_instruction_index(ip)?;
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

pub fn is_stack_relative(instruction: &Instruction, position: u32) -> bool {
    match instruction.op_kind(position) {
        OpKind::Register => instruction.op_register(position) == Register::RSP,
        OpKind::Memory => instruction.memory_base() == Register::RSP,
        _ => false,
    }
}

pub fn is_callee_saved(register: &Register) -> bool {
    match register {
        Register::RBX
        | Register::RBP
        | Register::R12
        | Register::R13
        | Register::R14
        | Register::R15 => true,
        _ => false,
    }
}
