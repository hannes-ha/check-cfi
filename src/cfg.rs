use std::collections::{HashSet, VecDeque};

use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use petgraph::graphmap::DiGraphMap;

use crate::analyze::{get_register_or_mem_base, Analyzer};

pub struct CallPath {
    pub entrypoint: u64,
    trusted_registers: HashSet<Register>,
    compare_ip: u64,
}

impl CallPath {
    fn new(entrypoint: u64, trusted_registers: HashSet<Register>, compare_ip: u64) -> Self {
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
    pub fn new(target_icall: Instruction, analyzer: &Analyzer) -> Result<Self, String> {
        let mut graph = DiGraphMap::<u64, ()>::new();
        let mut call_paths = Vec::<CallPath>::new();
        let icall_ip = target_icall.ip();
        let icall_target = get_register_or_mem_base(&target_icall, 0);

        graph.add_node(icall_ip);

        // track set of trusted registers to limit search backwards
        let mut queue = VecDeque::<(u64, HashSet<Register>, u64)>::new();
        queue.push_back((icall_ip, HashSet::default(), 0));

        while !queue.is_empty() {
            let Some((node_ip, mut trusted_registers, mut cmp_ip)) = queue.pop_front() else {
                break;
            };

            let instruction = analyzer.get_instruction(node_ip)?;
            let parents = analyzer.get_parents(node_ip)?;
            let mnemonic = instruction.mnemonic();

            // Stop at function border
            if analyzer.is_function_border(&node_ip) {
                call_paths.push(CallPath::new(node_ip, trusted_registers, cmp_ip));
                continue;
            }

            // trusted registers evolve from a cmp leading to a ud1
            if mnemonic == Mnemonic::Cmp {
                Analyzer::debug(icall_ip, "found cmp".to_string());

                let mut stack = analyzer.get_children(node_ip)?;
                let mut visited = HashSet::new();
                while let Some(cmp_child) = stack.pop() {
                    visited.insert(cmp_child.ip());
                    if cmp_child.mnemonic() == Mnemonic::Ud1 {
                        // the registers involved in the compare are now considered trusted
                        trusted_registers.insert(instruction.op0_register());
                        cmp_ip = instruction.ip();
                        Analyzer::debug(
                            icall_ip,
                            format!("Trusting {:?}", instruction.op0_register()),
                        );

                        match instruction.op1_kind() {
                            OpKind::Register => {
                                Analyzer::debug(
                                    icall_ip,
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
                        || graph.contains_node(cmp_child.ip())
                    {
                        analyzer
                            .get_children(cmp_child.ip())?
                            .iter()
                            .for_each(|gc| {
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
                call_paths.push(CallPath::new(node_ip, trusted_registers, cmp_ip));
                continue;
            }

            for parent in parents {
                let parent_ip = parent.ip();
                // add node if it doesnt already exist
                if !graph.contains_node(parent_ip) {
                    graph.add_node(parent_ip);
                    // we dont need to visit parents more than once
                    queue.push_back((parent_ip, trusted_registers.clone(), cmp_ip));
                }
                // else just add edge
                graph.add_edge(parent_ip, node_ip, ());
            }
        }

        Ok(Self {
            graph,
            call_paths,
            target_icall,
        })
    }

    pub fn cmp_found(&self) -> bool {
        return self.call_paths.iter().all(|path| path.compare_ip > 0);
    }

    fn untrust_dfs(
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
