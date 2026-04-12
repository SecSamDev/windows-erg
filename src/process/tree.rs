//! Process tree operations (kill tree, ancestors, etc.).

use std::collections::{HashMap, HashSet};

use super::processes::Process;
use super::types::{ProcessId, ProcessInfo};
use crate::error::Result;

impl Process {
    /// Kill this process and all its descendants.
    ///
    /// This will recursively kill all child processes first, then the parent.
    pub fn kill_tree(&self) -> Result<()> {
        Self::kill_tree_by_id(self.id())
    }

    /// Kill a process and all its descendants by process ID.
    pub fn kill_tree_by_id(pid: ProcessId) -> Result<()> {
        let mut buffer = Vec::with_capacity(8192);
        Self::kill_tree_by_id_with_buffer(pid, &mut buffer)
    }

    /// Kill a process tree using a reusable output buffer.
    pub fn kill_tree_by_id_with_buffer(
        pid: ProcessId,
        out_processes: &mut Vec<ProcessInfo>,
    ) -> Result<()> {
        Self::list_with_buffer(out_processes)?;
        let tree = build_process_tree(out_processes);

        // Collect all descendants
        let mut to_kill = HashSet::new();
        collect_descendants(pid, &tree, &mut to_kill);
        to_kill.insert(pid);

        // Kill in reverse order (children before parents)
        let mut kill_order: Vec<_> = to_kill.into_iter().collect();
        kill_order.sort_by_key(|&pid| std::cmp::Reverse(tree_depth(pid, &tree)));

        for kill_pid in kill_order {
            // Ignore errors - process might have already exited
            let _ = Self::kill_by_id(kill_pid);
        }

        Ok(())
    }

    /// Find the root ancestor of a process and kill the entire tree.
    ///
    /// This walks up the parent chain to find the topmost process,
    /// then kills that entire tree.
    pub fn kill_tree_from_root(pid: ProcessId) -> Result<()> {
        let mut buffer = Vec::with_capacity(8192);
        Self::kill_tree_from_root_with_buffer(pid, &mut buffer)
    }

    /// Kill tree from root using a reusable output buffer.
    pub fn kill_tree_from_root_with_buffer(
        pid: ProcessId,
        out_processes: &mut Vec<ProcessInfo>,
    ) -> Result<()> {
        Self::list_with_buffer(out_processes)?;
        let tree = build_process_tree(out_processes);

        // Find root ancestor
        let root = find_root_ancestor(pid, &tree);

        // Kill entire tree from root
        Self::kill_tree_by_id_with_buffer(root, out_processes)
    }
}

/// Build a parent->children mapping.
fn build_process_tree(processes: &[ProcessInfo]) -> HashMap<ProcessId, Vec<ProcessId>> {
    let mut tree: HashMap<ProcessId, Vec<ProcessId>> = HashMap::new();

    for proc in processes {
        if let Some(parent_pid) = proc.parent_pid {
            tree.entry(parent_pid).or_default().push(proc.pid);
        }
    }

    tree
}

/// Recursively collect all descendants of a process.
fn collect_descendants(
    pid: ProcessId,
    tree: &HashMap<ProcessId, Vec<ProcessId>>,
    result: &mut HashSet<ProcessId>,
) {
    if let Some(children) = tree.get(&pid) {
        for &child in children {
            if result.insert(child) {
                collect_descendants(child, tree, result);
            }
        }
    }
}

/// Calculate depth of a process in the tree (for kill ordering).
fn tree_depth(pid: ProcessId, tree: &HashMap<ProcessId, Vec<ProcessId>>) -> usize {
    if let Some(children) = tree.get(&pid) {
        1 + children
            .iter()
            .map(|&child| tree_depth(child, tree))
            .max()
            .unwrap_or(0)
    } else {
        0
    }
}

/// Find the root ancestor by walking up the parent chain.
fn find_root_ancestor(
    mut pid: ProcessId,
    parent_map: &HashMap<ProcessId, Vec<ProcessId>>,
) -> ProcessId {
    // Build reverse map (child -> parent)
    let mut child_to_parent: HashMap<ProcessId, ProcessId> = HashMap::new();
    for (&parent, children) in parent_map {
        for &child in children {
            child_to_parent.insert(child, parent);
        }
    }

    // Walk up to root
    let mut visited = HashSet::new();
    while let Some(&parent) = child_to_parent.get(&pid) {
        if !visited.insert(pid) {
            // Cycle detected, return current
            break;
        }
        pid = parent;
    }

    pid
}
