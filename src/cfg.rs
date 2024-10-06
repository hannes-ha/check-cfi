use std::collections::VecDeque;

use iced_x86::{FlowControl, Instruction, Mnemonic, Register};
use petgraph::{graphmap::DiGraphMap, visit::Dfs};

use crate::analyze::{get_register_or_mem_base, Analyzer};

impl Analyzer {
    pub fn generate_cfg(&self, ip: u64) -> Result<Cfg, String> {
        let mut cfg = Cfg::new();

        // insert the icall
        let icall_instruction = self.get_instruction(ip)?;
        cfg.add_node(ip);
        let icall_target = get_register_or_mem_base(&icall_instruction, 0);

        let mut queue = VecDeque::<u64>::new();
        queue.push_back(ip);

        while !queue.is_empty() {
            let Some(node_ip) = queue.pop_front() else {
                break;
            };

            let instruction = self.get_instruction(node_ip)?;
            let parents = self.get_parents(node_ip)?;
            let mnemonic = instruction.mnemonic();

            if mnemonic == Mnemonic::Push && instruction.op0_register() == Register::RBP
                || mnemonic == Mnemonic::Push && instruction.op0_register() == Register::RSP
                || instruction.flow_control() == FlowControl::Interrupt
                || instruction.flow_control() == FlowControl::Return
            {
                cfg.entrypoints.push(node_ip);
                continue;
            }
            // if mnemonic == Mnemonic::Mov && instruction.op0_register() == icall_target {
            //     cfg.entrypoints.push(node_ip);
            //     continue;
            // }

            for parent in parents {
                let parent_ip = parent.ip();
                // add node if it doesnt already exist
                if !cfg.contains_node(parent_ip) {
                    cfg.add_node(parent_ip);
                    // we dont need to visit parents more than once
                    queue.push_back(parent_ip);
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
            FlowControl::Call | FlowControl::Next | FlowControl::ConditionalBranch => {
                jump_prevs.push(chronological_prev)
            }
            _ => (),
        }
        Ok(jump_prevs)
    }
}

pub struct Cfg {
    pub fwd_graph: DiGraphMap<u64, ()>,
    // we need a directed graph to be able to dfs "one way", but also a way to traverse the
    // instructions backwards
    pub bwd_graph: DiGraphMap<u64, ()>,
    pub entrypoints: Vec<u64>,
}

impl Cfg {
    pub fn new() -> Self {
        Cfg {
            fwd_graph: DiGraphMap::<u64, ()>::with_capacity(100, 200),
            bwd_graph: DiGraphMap::<u64, ()>::with_capacity(100, 200),
            entrypoints: Vec::new(),
        }
    }

    pub fn add_node(&mut self, value: u64) -> u64 {
        self.fwd_graph.add_node(value)
    }

    pub fn contains_node(&mut self, value: u64) -> bool {
        self.fwd_graph.contains_node(value)
    }

    pub fn add_edge(&mut self, from: u64, to: u64) {
        self.fwd_graph.add_edge(from, to, ());
    }

    pub fn find_compare(&self, analyzer: &Analyzer, entrypoint: u64) -> Result<u64, String> {
        let mut dfs = Dfs::new(&self.fwd_graph, entrypoint);

        // address of the compare instruction
        let mut cmp_ip = 0;
        let mut ud1_found = false;

        while let Some(ip) = dfs.next(&self.fwd_graph) {
            let instruction = analyzer.get_instruction(ip)?;

            if instruction.mnemonic() == Mnemonic::Cmp {
                cmp_ip = instruction.ip();
                continue;
            }

            if instruction.mnemonic() == Mnemonic::Ud1 && cmp_ip > 0 {
                ud1_found = true;
                break;
            }

            if instruction.is_jcc_short_or_near() && cmp_ip > 0 {
                let jcc_target = analyzer.get_instruction(instruction.near_branch_target())?;
                if jcc_target.mnemonic() == Mnemonic::Ud1 {
                    // compare and ud1 branch found. We are done
                    ud1_found = true;
                    break;
                }
            }

            // TODO: slack for mov between cmp and jcc
            cmp_ip = 0;
        }
        if cmp_ip > 0 && ud1_found {
            return Ok(cmp_ip);
        }
        Err("Could not find compare".to_string())
    }

    pub fn assert_call_target_trusted() {}

    pub fn assert_call_register_untouched() {}
}
