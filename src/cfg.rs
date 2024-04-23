use iced_x86::{OpAccess, Register};
use petgraph::{algo::has_path_connecting, graphmap::DiGraphMap, visit::Dfs};

use crate::analyze::Analyzer;

pub struct Cfg {
    pub fwd_graph: DiGraphMap<u64, ()>,
    // we need a directed graph to be able to dfs "one way", but also a way to traverse the
    // instructions backwards
    pub bwd_graph: DiGraphMap<u64, ()>,
    pub entrypoints: Vec<u64>,
    cmp_ip: u64,
}

impl Cfg {
    pub fn new() -> Self {
        Cfg {
            fwd_graph: DiGraphMap::<u64, ()>::with_capacity(100, 200),
            bwd_graph: DiGraphMap::<u64, ()>::with_capacity(100, 200),
            entrypoints: Vec::new(),
            cmp_ip: 0,
        }
    }

    pub fn cmp_found(&self) -> bool {
        return self.cmp_ip > 0;
    }

    pub fn set_cmp_ip(&mut self, ip: u64) {
        if self.cmp_found() && ip != self.cmp_ip {
            panic!("Duplicate cmp found");
        }
        self.cmp_ip = ip;
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

    // visits the graph from the entrypoints and asserts that a given register is not written to
    // between the entrypoints and the goal
    pub fn assert_register_untouched(
        &self,
        analyzer: &Analyzer,
        goal: u64,
        register: Register,
    ) -> Result<(), String> {
        if register == Register::None {
            panic!("Register none cannot be checked");
        }
        for entrypoint in &self.entrypoints {
            let mut dfs = Dfs::new(&self.fwd_graph, *entrypoint);
            while let Some(ip) = dfs.next(&self.fwd_graph) {
                let instruction = analyzer.get_instruction(ip)?;
                let info = analyzer.get_instruction_info(&instruction);

                let touched = info.used_registers().iter().any(|register_use| {
                    return register_use.register() == register
                        && match register_use.access() {
                            OpAccess::Write
                            | OpAccess::CondWrite
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite => true,
                            _ => false,
                        };
                });

                // if this node touches the register, check if there is a path from here to the
                // goal
                if touched && has_path_connecting(&self.fwd_graph, ip, goal, None) {
                    return Err(format!(
                        "Found connecting path between touching register at 0x{:x} and icall",
                        ip
                    ));
                }
            }
        }

        Ok(())
    }
}
