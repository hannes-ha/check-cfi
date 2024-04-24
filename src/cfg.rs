use std::collections::HashSet;

use iced_x86::{Instruction, OpAccess, Register};
use petgraph::graphmap::DiGraphMap;

use crate::analyze::{get_register_or_mem_base, Analyzer};

pub struct Cfg {
    pub fwd_graph: DiGraphMap<u64, ()>,
    // we need a directed graph to be able to dfs "one way", but also a way to traverse the
    // instructions backwards
    pub bwd_graph: DiGraphMap<u64, ()>,
    pub entrypoints: Vec<(u64, HashSet<Register>, u64)>,
    target_icall: Instruction,
}

impl Cfg {
    pub fn new(target_icall: Instruction) -> Self {
        Cfg {
            fwd_graph: DiGraphMap::<u64, ()>::with_capacity(100, 200),
            bwd_graph: DiGraphMap::<u64, ()>::with_capacity(100, 200),
            entrypoints: Vec::new(),
            target_icall,
        }
    }

    pub fn cmp_found(&self) -> bool {
        return self.entrypoints.iter().all(|(_, _, cmp_ip)| *cmp_ip > 0);
    }

    pub fn add_node(&mut self, value: u64) -> u64 {
        self.fwd_graph.add_node(value);
        self.bwd_graph.add_node(value)
    }

    pub fn contains_node(&mut self, value: u64) -> bool {
        self.fwd_graph.contains_node(value)
    }

    pub fn add_edge(&mut self, from: u64, to: u64) {
        self.fwd_graph.add_edge(from, to, ());
        self.bwd_graph.add_edge(to, from, ());
    }

    pub fn untrust_dfs(
        &self,
        analyzer: &Analyzer,
        entry_point: u64,
        trusted_registers: HashSet<Register>,
    ) -> Result<(), String> {
        let mut stack = vec![(entry_point, trusted_registers)];
        let mut visited = HashSet::<u64>::new();

        // when the icall is reached, check wether the call register is trusted
        while let Some((current_node, mut local_trusted)) = stack.pop() {
            visited.insert(current_node);
            if current_node == self.target_icall.ip() {
                match local_trusted.contains(&get_register_or_mem_base(&self.target_icall, 0)) {
                    true => continue,
                    false => {
                        return Err(format!(
                            "Call target not trusted when looking from 0x{:x}",
                            entry_point
                        ))
                    }
                };
            }

            // dead end, this is fine
            if self.fwd_graph.neighbors(current_node).count() == 0 {
                continue;
            };

            let instruction = analyzer.get_instruction(current_node)?;
            let info = analyzer.get_instruction_info(&instruction);

            let written_registers = info
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
                .collect::<Vec<_>>();

            let read_registers = info
                .used_registers()
                .iter()
                .filter(|register_use| match register_use.access() {
                    OpAccess::Read => true,
                    _ => false,
                })
                .map(|register_read_use| register_read_use.register())
                .collect::<Vec<_>>();

            // if all read registers are safe, add written registers to trusted.
            // otherwise remove all from trusted
            if read_registers.iter().all(|r| local_trusted.contains(&r)) {
                written_registers.iter().for_each(|w_r| {
                    local_trusted.insert(*w_r);
                });
            } else {
                written_registers.iter().for_each(|w_r| {
                    local_trusted.remove(&w_r);
                });
            }

            // this is flawed, as paths leading to the same node but with different states are
            // discarded. dont know how to solve
            for nb in self.fwd_graph.neighbors(current_node) {
                if !visited.contains(&nb) {
                    stack.push((nb, local_trusted.clone()));
                }
            }
        }

        // all fine!
        Ok(())
    }

    // visits the graph from the entrypoints and asserts that a given register is not written to
    // between the compare and the goal, for each entrypoint as these might have different sets of
    // trusted registers
    pub fn assert_icall_to_trusted_register(&self, analyzer: &Analyzer) -> Result<(), String> {
        for (_, trusted_registers, cmp_ip) in &self.entrypoints {
            self.untrust_dfs(&analyzer, *cmp_ip, trusted_registers.clone())?;
        }
        Ok(())
    }
}
