use std::collections::HashSet;

use iced_x86::{Instruction, Register};
use petgraph::graphmap::DiGraphMap;

use crate::analyze::{get_register_or_mem_base, Analyzer};

pub struct CallPath {
    pub entrypoint: u64,
    pub trusted_registers: HashSet<Register>,
    pub compare_ip: u64,
}

impl CallPath {
    pub fn new(entrypoint: u64, trusted_registers: HashSet<Register>, compare_ip: u64) -> Self {
        Self {
            entrypoint,
            trusted_registers,
            compare_ip,
        }
    }
}

pub struct Cfg {
    pub graph: DiGraphMap<u64, ()>,
    pub call_paths: Vec<CallPath>,
    target_icall: Instruction,
}

impl Cfg {
    pub fn new(target_icall: Instruction) -> Self {
        Cfg {
            graph: DiGraphMap::<u64, ()>::with_capacity(100, 200),
            call_paths: Vec::new(),
            target_icall,
        }
    }

    pub fn cmp_found(&self) -> bool {
        return self.call_paths.iter().all(|path| path.compare_ip > 0);
    }

    pub fn add_node(&mut self, value: u64) -> u64 {
        self.graph.add_node(value)
    }

    pub fn contains_node(&mut self, value: u64) -> bool {
        self.graph.contains_node(value)
    }

    pub fn add_edge(&mut self, from: u64, to: u64) -> Option<()> {
        self.graph.add_edge(from, to, ())
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
            if self.graph.neighbors(current_node).count() == 0 {
                continue;
            };

            let written_registers = analyzer.get_written_registers(current_node)?;
            let read_registers = analyzer.get_read_registers(current_node)?;

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
            self.graph.neighbors(current_node).for_each(|nb| {
                if !visited.contains(&nb) {
                    stack.push((nb, local_trusted.clone()));
                }
            })
        }

        // all fine!
        Ok(())
    }

    // visits the graph from the entrypoints and asserts that a given register is not written to
    // between the compare and the goal, for each entrypoint as these might have different sets of
    // trusted registers
    pub fn assert_icall_to_trusted_register(&self, analyzer: &Analyzer) -> Result<(), String> {
        for path in &self.call_paths {
            self.untrust_dfs(&analyzer, path.compare_ip, path.trusted_registers.clone())?;
        }
        Ok(())
    }
}
