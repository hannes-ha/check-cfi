use std::collections::{HashSet, VecDeque};

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};
use petgraph::graphmap::DiGraphMap;

use crate::analyze::{get_register_or_mem_base, is_callee_saved, is_stack_relative, Analyzer};

#[derive(Clone)]
pub struct CallPath {
    pub entrypoint: u64,
    trusted_registers: HashSet<Register>,
    compare_ip: u64,
    load_ip: u64,
}

impl CallPath {
    fn new(
        entrypoint: u64,
        trusted_registers: HashSet<Register>,
        compare_ip: u64,
        load_ip: u64,
    ) -> Self {
        Self {
            entrypoint,
            trusted_registers,
            compare_ip,
            load_ip,
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
        let mut queue = VecDeque::<CallPath>::new();
        queue.push_back(CallPath::new(icall_ip, HashSet::default(), 0, 0));

        while !queue.is_empty() {
            let Some(mut call_path) = queue.pop_front() else {
                break;
            };

            let instruction = analyzer.get_instruction(call_path.entrypoint)?;
            let mnemonic = instruction.mnemonic();

            // Stop at function border
            if analyzer.is_function_border(&call_path.entrypoint)
                || instruction.flow_control() == FlowControl::Return
                || (instruction.mnemonic() == Mnemonic::Push
                    && instruction.op0_register() == Register::RBP)
            {
                call_paths.push(call_path);
                continue;
            }

            // trusted registers evolve from a cmp leading to a ud1
            if mnemonic == Mnemonic::Cmp
                && !is_stack_relative(&instruction, 0)
                && !is_stack_relative(&instruction, 1)
            {
                Analyzer::debug(icall_ip, "found cmp".to_string());

                let mut stack = analyzer.get_children(call_path.entrypoint)?;
                let mut visited = HashSet::new();
                while let Some(cmp_child) = stack.pop() {
                    visited.insert(cmp_child.ip());
                    if cmp_child.mnemonic() == Mnemonic::Ud1 {
                        // the registers involved in the compare are now considered trusted
                        call_path
                            .trusted_registers
                            .insert(instruction.op0_register());
                        call_path.compare_ip = instruction.ip();

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
                                call_path
                                    .trusted_registers
                                    .insert(instruction.op1_register());
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

            // moving into trusted registers propagate trust
            if mnemonic == Mnemonic::Mov {
                if call_path
                    .trusted_registers
                    .contains(&instruction.op0_register())
                    && !is_stack_relative(&instruction, 1)
                {
                    call_path
                        .trusted_registers
                        .insert(instruction.op1_register());

                    if instruction.op1_kind() == OpKind::Register {
                        call_path
                            .trusted_registers
                            .remove(&instruction.op0_register());
                    }
                }
            }

            // LEA from jump table considered trusted
            if mnemonic == Mnemonic::Lea {
                if is_load_from_jmp_table(&analyzer, instruction) {
                    call_path
                        .trusted_registers
                        .insert(instruction.op0_register());
                    call_path.load_ip = instruction.ip();
                }
            }

            let parents = analyzer.get_parents(call_path.entrypoint)?;

            // if the call register is trusted, or we are at a dead end we can stop looking at this leg
            if call_path.trusted_registers.contains(&icall_target) {
                call_paths.push(call_path);
                continue;
            }

            for parent in parents {
                let parent_ip = parent.ip();
                // add node if it doesnt already exist
                if !graph.contains_node(parent_ip) {
                    graph.add_node(parent_ip);
                    // we dont need to visit parents more than once
                    let mut parent_path = call_path.clone();
                    parent_path.entrypoint = parent_ip;
                    queue.push_back(parent_path);
                }
                // else just add edge
                graph.add_edge(parent_ip, call_path.entrypoint, ());
            }
        }

        Ok(Self {
            graph,
            call_paths,
            target_icall,
        })
    }

    pub fn cmp_found(&self) -> bool {
        return self
            .call_paths
            .iter()
            .all(|path| path.compare_ip > 0 || path.load_ip > 0);
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
            // except the stack relative wich may never be trusted
            // otherwise remove all from trusted
            if read_registers.iter().all(|r| local_trusted.contains(&r)) {
                written_registers.iter().for_each(|&w_r| {
                    if w_r != Register::RSP {
                        local_trusted.insert(w_r);
                    }
                });
            } else {
                written_registers.iter().for_each(|w_r| {
                    local_trusted.remove(&w_r);
                });
            }

            let instruction = analyzer.get_instruction(current_node)?;
            if instruction.mnemonic() == Mnemonic::Lea
                && is_load_from_jmp_table(&analyzer, instruction)
            {
                Analyzer::debug(
                    self.target_icall.ip(),
                    format!("found load from jmp table at 0x{:x}", instruction.ip()),
                );
                if !is_stack_relative(&instruction, 0) {
                    local_trusted.insert(instruction.op0_register());
                }
            }

            // if we pass a call, untrust everything that is not callee-saved
            if instruction.mnemonic() == Mnemonic::Call {
                let current_trusted = local_trusted.clone();
                current_trusted.iter().for_each(|ct| {
                    if !is_callee_saved(ct) {
                        local_trusted.remove(&ct);
                    }
                })
            }

            // TODO: paths leading to the same node but with different states are discarded
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

// Handle edge case where LEA reg [read-only] -> call reg
// Not really an indirect call
fn is_load_from_jmp_table(analyzer: &Analyzer, lea_instruction: Instruction) -> bool {
    let lea_target = lea_instruction.memory_displacement64();
    // this indirectly checks that the load is from within .text segment
    // i.e. read-only memory
    let Ok(target_instruction) = analyzer.get_instruction(lea_target) else {
        return false;
    };

    if target_instruction.flow_control() != FlowControl::UnconditionalBranch {
        return false;
    }

    let Ok(instruction_index) = analyzer.get_instruction_index(target_instruction.ip()) else {
        return false;
    };

    // if previous instruction is an interrupt
    let Ok(prev_instruction) = analyzer.get_instruction_from_index(instruction_index - 1) else {
        return false;
    };
    // and the next instruction is an interrup
    let Ok(next_instruction) = analyzer.get_instruction_from_index(instruction_index + 1) else {
        return false;
    };
    // this is very likely the jump table
    return prev_instruction.flow_control() == FlowControl::Interrupt
        && next_instruction.flow_control() == FlowControl::Interrupt;
}
