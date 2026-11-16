//! A block's aggregation tree and the coordinator's dispatch policy. Pure: no proving, no I/O.
//!
//! Leaves are unpacked as EIP-8288 prices them: each generic or batch leaf is its own initial step; signatures are
//! grouped `sigs_per_node` to a step. Merges take up to `fanin` children, level by level, to one root. The scheduler
//! hands a free worker the ready node with the longest estimated path to the root (critical path first), preferring
//! the node whose children's proofs it already holds.

/// What one initial step verifies directly, by index into the plan's input files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// `count` signatures from `from` in a signature file.
    Sigs {
        file: usize,
        from: usize,
        count: usize,
    },
    /// One generic leaf, its claims as ordinary leanSTARK dependencies.
    Generic { file: usize },
    /// One sponsored leaf (ethereum/EIPs#12664): its first `retain` claims as batch dependencies, and its payment.
    Batch { file: usize, retain: usize },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub id: usize,
    pub depth: usize,
    pub inputs: Vec<Input>,
    pub children: Vec<usize>,
    pub parent: Option<usize>,
    /// The root of a block with batch dependencies proves the finalized statement.
    pub finalize: bool,
    /// Used only to order dispatch; never reported.
    pub estimate_s: f64,
}

impl Node {
    pub fn kind(&self) -> &'static str {
        match (self.children.is_empty(), self.inputs.first()) {
            (false, _) => "merge",
            (true, Some(Input::Sigs { .. })) => "sigs",
            (true, Some(Input::Generic { .. })) => "generic",
            (true, Some(Input::Batch { .. })) => "batch",
            (true, None) => "empty",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PlanSpec {
    /// `(file, count)` per signature file.
    pub sigs: Vec<(usize, usize)>,
    pub generic: Vec<usize>,
    /// `(file, retained claims)` per sponsored leaf.
    pub batch: Vec<(usize, usize)>,
    pub sigs_per_node: usize,
    pub fanin: usize,
    pub max_inner_proofs_per_step: usize,
    pub finalize: bool,
}

/// Ordering estimates (seconds, roughly an M2 Max at 11 threads): only their ratios matter.
fn estimate(inputs: &[Input], children: usize) -> f64 {
    let leaf: f64 = inputs
        .iter()
        .map(|i| match i {
            Input::Sigs { count, .. } => 0.016 * *count as f64,
            Input::Generic { .. } => 1.0,
            Input::Batch { retain, .. } => 1.0 + 0.0005 * *retain as f64,
        })
        .sum();
    leaf + if children > 0 {
        0.15 + 0.15 * children as f64
    } else {
        0.0
    }
}

pub fn plan(spec: &PlanSpec) -> Result<Vec<Node>, String> {
    if spec.fanin < 2 || spec.fanin > spec.max_inner_proofs_per_step {
        return Err(format!(
            "fan-in {} must be 2..=MAX_INNER_PROOFS_PER_STEP ({})",
            spec.fanin, spec.max_inner_proofs_per_step
        ));
    }
    if spec.sigs_per_node == 0 {
        return Err("sigs_per_node must be positive".into());
    }
    let mut nodes: Vec<Node> = Vec::new();
    let mut leaf = |inputs: Vec<Input>| {
        let id = nodes.len();
        let estimate_s = estimate(&inputs, 0);
        nodes.push(Node {
            id,
            depth: 0,
            inputs,
            children: vec![],
            parent: None,
            finalize: false,
            estimate_s,
        });
    };
    for &(file, count) in &spec.sigs {
        for from in (0..count).step_by(spec.sigs_per_node) {
            leaf(vec![Input::Sigs {
                file,
                from,
                count: spec.sigs_per_node.min(count - from),
            }]);
        }
    }
    for &file in &spec.generic {
        leaf(vec![Input::Generic { file }]);
    }
    for &(file, retain) in &spec.batch {
        leaf(vec![Input::Batch { file, retain }]);
    }
    if nodes.is_empty() {
        return Err("the block has no dependencies".into());
    }
    let mut level: Vec<usize> = (0..nodes.len()).collect();
    let mut depth = 0;
    while level.len() > 1 {
        depth += 1;
        let mut next = Vec::new();
        for group in level.chunks(spec.fanin) {
            // A lone remainder rises a level unchanged: a one-child step would only add latency.
            if let [only] = group {
                next.push(*only);
                continue;
            }
            let id = nodes.len();
            for &c in group {
                nodes[c].parent = Some(id);
            }
            nodes.push(Node {
                id,
                depth,
                inputs: vec![],
                children: group.to_vec(),
                parent: None,
                finalize: false,
                estimate_s: estimate(&[], group.len()),
            });
            next.push(id);
        }
        level = next;
    }
    nodes[level[0]].finalize = spec.finalize;
    Ok(nodes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Waiting,
    Ready,
    Running(usize),
    Done(usize),
}

pub struct Scheduler {
    nodes: Vec<Node>,
    state: Vec<State>,
    pending_children: Vec<usize>,
    /// Estimated seconds from a node's start to the root's end: the critical-path priority.
    rank: Vec<f64>,
    output_bytes: Vec<u64>,
    root: usize,
}

impl Scheduler {
    pub fn new(nodes: Vec<Node>) -> Self {
        let n = nodes.len();
        let root = nodes
            .iter()
            .position(|x| x.parent.is_none())
            .expect("a root");
        let mut rank = vec![0.0; n];
        // Parents have higher ids than their children, so one reverse pass sees each parent first.
        for i in (0..n).rev() {
            rank[i] = nodes[i].estimate_s + nodes[i].parent.map_or(0.0, |p| rank[p]);
        }
        let pending_children: Vec<usize> = nodes.iter().map(|x| x.children.len()).collect();
        let state = pending_children
            .iter()
            .map(|&c| if c == 0 { State::Ready } else { State::Waiting })
            .collect();
        Self {
            nodes,
            state,
            pending_children,
            rank,
            output_bytes: vec![0; n],
            root,
        }
    }

    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    pub fn root(&self) -> usize {
        self.root
    }

    /// The worker holding a finished node's proof.
    pub fn location(&self, id: usize) -> Option<usize> {
        match self.state[id] {
            State::Done(w) => Some(w),
            _ => None,
        }
    }

    /// Bytes of `id`'s children's proofs already on `worker`.
    fn local_bytes(&self, id: usize, worker: usize) -> u64 {
        self.nodes[id]
            .children
            .iter()
            .filter(|&&c| self.state[c] == State::Done(worker))
            .map(|&c| self.output_bytes[c])
            .sum()
    }

    /// Assigns `worker` the ready node with the highest rank, then the most local input bytes, then the lowest id.
    pub fn next_for(&mut self, worker: usize) -> Option<usize> {
        let best = (0..self.nodes.len())
            .filter(|&i| self.state[i] == State::Ready)
            .max_by(|&a, &b| {
                self.rank[a]
                    .total_cmp(&self.rank[b])
                    .then(
                        self.local_bytes(a, worker)
                            .cmp(&self.local_bytes(b, worker)),
                    )
                    .then(b.cmp(&a))
            })?;
        self.state[best] = State::Running(worker);
        Some(best)
    }

    pub fn complete(&mut self, id: usize, worker: usize, output_bytes: u64) {
        assert_eq!(
            self.state[id],
            State::Running(worker),
            "node {id} was not running on worker {worker}"
        );
        self.state[id] = State::Done(worker);
        self.output_bytes[id] = output_bytes;
        if let Some(p) = self.nodes[id].parent {
            self.pending_children[p] -= 1;
            if self.pending_children[p] == 0 {
                self.state[p] = State::Ready;
            }
        }
    }

    pub fn finished(&self) -> bool {
        matches!(self.state[self.root], State::Done(_))
    }
}

/// The list schedule of `durations` on `workers` under this scheduler's policy with no transfer time: a modelled
/// comparison for a measured run, never a substitute for it.
pub fn simulate(nodes: Vec<Node>, durations: &[f64], workers: usize) -> f64 {
    let mut s = Scheduler::new(nodes);
    let mut free_at = vec![0.0f64; workers];
    let mut running: Vec<(f64, usize, usize)> = Vec::new();
    let mut now = 0.0;
    loop {
        for w in 0..workers {
            if free_at[w] <= now
                && !running.iter().any(|r| r.2 == w)
                && let Some(id) = s.next_for(w)
            {
                let end = now + durations[id];
                free_at[w] = end;
                running.push((end, id, w));
            }
        }
        if running.is_empty() {
            break;
        }
        running.sort_by(|a, b| a.0.total_cmp(&b.0));
        let (end, id, w) = running.remove(0);
        now = end;
        s.complete(id, w, 0);
    }
    assert!(s.finished(), "every node ran");
    now
}

/// The measured critical path: the most time along any leaf-to-root chain, each node counted from its dispatch to
/// its completion (transfers included).
pub fn critical_path(nodes: &[Node], spans: &[f64]) -> f64 {
    let mut best = vec![0.0f64; nodes.len()];
    for n in nodes {
        best[n.id] = spans[n.id] + n.children.iter().map(|&c| best[c]).fold(0.0, f64::max);
    }
    nodes
        .iter()
        .filter(|n| n.parent.is_none())
        .map(|n| best[n.id])
        .fold(0.0, f64::max)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(sigs: usize, generic: usize, batch: usize, fanin: usize) -> PlanSpec {
        PlanSpec {
            sigs: if sigs > 0 { vec![(0, sigs)] } else { vec![] },
            generic: (1..=generic).collect(),
            batch: (0..batch).map(|i| (100 + i, 1)).collect(),
            sigs_per_node: 64,
            fanin,
            max_inner_proofs_per_step: 16,
            finalize: batch > 0,
        }
    }

    #[test]
    fn plans_unpacked_leaves_and_bounded_merges() {
        let nodes = plan(&spec(130, 5, 2, 4)).unwrap();
        let leaves: Vec<_> = nodes.iter().filter(|n| n.children.is_empty()).collect();
        // 130 signatures in 64s: 3 nodes; then one node per generic and per batch leaf.
        assert_eq!(leaves.len(), 3 + 5 + 2);
        assert!(leaves.iter().all(|n| n.inputs.len() == 1));
        let sigs: usize = leaves
            .iter()
            .filter_map(|n| match n.inputs[0] {
                Input::Sigs { count, .. } => Some(count),
                _ => None,
            })
            .sum();
        assert_eq!(sigs, 130);
        assert!(nodes.iter().all(|n| n.children.len() <= 4));
        // 10 leaves -> 3 -> 1.
        let root = nodes.iter().find(|n| n.parent.is_none()).unwrap();
        assert_eq!((root.depth, nodes.len()), (2, 10 + 3 + 1));
        assert!(root.finalize);
        assert_eq!(nodes.iter().filter(|n| n.finalize).count(), 1);
        for n in &nodes {
            for &c in &n.children {
                assert_eq!(nodes[c].parent, Some(n.id));
                assert!(c < n.id);
            }
        }
    }

    #[test]
    fn a_lone_remainder_rises_without_a_step() {
        // 5 leaves at fan-in 2: (0,1) (2,3) 4 -> (5,6) 4 -> (7,4).
        let mut sp = spec(5, 0, 0, 2);
        sp.sigs_per_node = 1;
        let nodes = plan(&sp).unwrap();
        assert!(
            nodes
                .iter()
                .all(|n| n.children.is_empty() || n.children.len() == 2)
        );
        assert_eq!(nodes.len(), 5 + 4);
        assert_eq!(nodes[4].parent, Some(8));
    }

    #[test]
    fn a_single_leaf_is_its_own_root() {
        let nodes = plan(&spec(0, 0, 1, 4)).unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(nodes[0].finalize && nodes[0].parent.is_none());
    }

    #[test]
    fn rejects_fanin_beyond_the_step_bound_and_empty_blocks() {
        assert!(plan(&spec(10, 0, 0, 17)).is_err());
        assert!(plan(&spec(10, 0, 0, 1)).is_err());
        assert!(plan(&spec(0, 0, 0, 4)).is_err());
    }

    #[test]
    fn dispatch_respects_dependencies_and_never_repeats() {
        let nodes = plan(&spec(64 * 9, 7, 0, 3)).unwrap();
        let n = nodes.len();
        let mut s = Scheduler::new(nodes.clone());
        let mut done = vec![false; n];
        let mut order = Vec::new();
        // Two workers; complete in an adversarial order: the most recently dispatched first.
        let mut running: Vec<(usize, usize)> = Vec::new();
        while !s.finished() {
            for w in 0..2 {
                if !running.iter().any(|r| r.1 == w)
                    && let Some(id) = s.next_for(w)
                {
                    assert!(
                        nodes[id].children.iter().all(|&c| done[c]),
                        "children first"
                    );
                    assert!(!order.contains(&id), "dispatched once");
                    order.push(id);
                    running.push((id, w));
                }
            }
            let (id, w) = running.pop().expect("progress");
            done[id] = true;
            s.complete(id, w, 1000);
        }
        assert_eq!(order.len(), n);
    }

    #[test]
    fn critical_path_first_then_locality() {
        // A generic leaf (est. 1 s) outranks a 1-signature leaf.
        let mut sp = spec(1, 1, 0, 2);
        sp.sigs_per_node = 1;
        let mut s = Scheduler::new(plan(&sp).unwrap());
        let first = s.next_for(0).unwrap();
        assert_eq!(s.nodes()[first].kind(), "generic");
        // Four equal leaves, two merges: the worker holding both of a merge's children gets that merge.
        let mut sp = spec(4, 0, 0, 2);
        sp.sigs_per_node = 1;
        let mut s = Scheduler::new(plan(&sp).unwrap());
        for (w, id) in [(1, 0), (1, 1), (0, 2), (0, 3)] {
            assert_eq!(s.next_for(w), Some(id));
        }
        for (w, id) in [(1, 0), (1, 1), (0, 2), (0, 3)] {
            s.complete(id, w, 10);
        }
        let merges: Vec<usize> = s
            .nodes()
            .iter()
            .filter(|n| n.depth == 1)
            .map(|n| n.id)
            .collect();
        assert_eq!(s.next_for(0), Some(merges[1]));
        assert_eq!(s.next_for(1), Some(merges[0]));
    }

    #[test]
    fn simulation_and_critical_path_on_a_known_tree() {
        // 4 leaves of 1 s, 2 merges of 0.5 s, a root of 0.5 s.
        let mut sp = spec(4, 0, 0, 2);
        sp.sigs_per_node = 1;
        let nodes = plan(&sp).unwrap();
        let d: Vec<f64> = nodes
            .iter()
            .map(|n| if n.children.is_empty() { 1.0 } else { 0.5 })
            .collect();
        assert_eq!(simulate(nodes.clone(), &d, 1), 4.0 + 1.5);
        assert_eq!(simulate(nodes.clone(), &d, 2), 2.0 + 0.5 + 0.5);
        assert_eq!(simulate(nodes.clone(), &d, 4), 1.0 + 0.5 + 0.5);
        assert_eq!(critical_path(&nodes, &d), 2.0);
    }
}
