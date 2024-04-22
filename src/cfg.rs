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
        self.fwd_graph.add_node(value)
    }

    pub fn contains_node(&mut self, value: u64) -> bool {
        self.fwd_graph.contains_node(value)
    }

    pub fn add_edge(&mut self, from: u64, to: u64) {
        self.fwd_graph.add_edge(from, to, ());
    }

    // TODO: flip logic for bwd_graph
    // shold use backward graph
    pub fn find_compare(&self, analyzer: &Analyzer, entrypoint: u64) -> Result<u64, String> {
        let mut dfs = Dfs::new(&self.bwd_graph, entrypoint);

        // address of the compare instruction
        let mut cmp_ip = 0;
        let mut ud1_found = false;

        while let Some(ip) = dfs.next(&self.bwd_graph) {
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
