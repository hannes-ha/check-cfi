use std::collections::{HashMap, HashSet};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfo, InstructionInfoFactory,
    OpAccess, OpKind, Register,
};

use crate::{cfg::Cfg, io};

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

    pub fn get_parents(&self, ip: u64) -> Result<Vec<Instruction>, String> {
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
