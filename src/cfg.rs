use core::panic;

use iced_x86::Mnemonic;
use petgraph::{graphmap::DiGraphMap, visit::Dfs};

use crate::analyze::Analyzer;

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

    // looks backwards for the ud1 and related compare
    pub fn find_compare(&self, analyzer: &Analyzer, entrypoint: u64) -> Result<u64, String> {
        let mut dfs = Dfs::new(&self.bwd_graph, entrypoint);

        // address of the compare instruction
        let mut cmp_ip = 0;
        let mut ud1_found = false;

        let mut itt = 0;
        while let Some(ip) = dfs.next(&self.bwd_graph) {
            itt += 1;
            let instruction = analyzer.get_instruction(ip)?;

            if instruction.mnemonic() == Mnemonic::Ud1 {
                if ud1_found {
                    panic!("duplicate ud1");
                }
                ud1_found = true;
                continue;
            }

            if instruction.is_jcc_short_or_near() || instruction.is_jmp_short_or_near() {
                let jcc_target = analyzer.get_instruction(instruction.near_branch_target())?;
                if jcc_target.mnemonic() == Mnemonic::Ud1 {
                    if ud1_found {
                        panic!("duplicate ud1");
                    }
                    ud1_found = true;
                    continue;
                }
            }

            if instruction.mnemonic() == Mnemonic::Cmp && ud1_found {
                cmp_ip = instruction.ip();
                break;
            }
        }

        if cmp_ip > 0 && ud1_found {
            return Ok(cmp_ip);
        }
        Err(format!("could not find compare after {} iterations", itt))
    }
}
