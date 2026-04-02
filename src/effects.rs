// SPDX-License-Identifier: CC0-1.0

//! Side effect analysis for Simplicity programs.
//!
//! This module provides types for tracking what parts of the transaction
//! environment a Simplicity program reads ([`TransactionField`]), and which
//! nodes can cause script failure (write effects).
//!
//! The data is intended to be collected into an [`EffectSummary`] per AST node
//! via a bottom-up pass, enabling two analyses:
//!
//! 1. **Completeness**: flag branches that have no write effect (cannot fail).
//! 2. **Malleability**: identify transaction fields not committed to by the program.

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::sync::Arc;

use crate::dag::{DagLike, MaxSharing};
use crate::jet::Jet;
use crate::node::{Commit, CommitData, CommitNode, Inner, Marker, Node, RedeemNode};
use crate::types::arrow::FinalArrow;

/// Selects which input a field refers to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InputSelector {
    /// The current input (the one being spent).
    Current,
    /// A specific input, selected by index at runtime.
    Indexed,
    /// All inputs.
    All,
}

/// Selects which output a field refers to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OutputSelector {
    /// A specific output, selected by index at runtime.
    Indexed,
    /// All outputs.
    All,
}

/// A primitive transaction field that a jet may read from its environment.
///
/// High-level hash jets (e.g. `sig_all_hash`) are denormalized into their
/// constituent primitive fields so that malleability analysis can identify
/// which parts of the transaction are not covered by the program.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TransactionField {
    // ── Transaction-level ──────────────────────────────────────────────────
    /// Transaction version.
    Version,
    /// Transaction lock time.
    Locktime,
    /// Number of inputs.
    InputCount,
    /// Number of outputs.
    OutputCount,

    // ── Input fields ───────────────────────────────────────────────────────
    /// Previous outpoint (txid + vout) of an input.
    InputPrevOutpoint(InputSelector),
    /// Sequence number of an input.
    InputSequence(InputSelector),
    /// Value (in satoshis) of an input.
    InputValue(InputSelector),
    /// Script-sig hash of an input.
    InputScriptSigHash(InputSelector),
    /// Annex hash of an input (if present).
    InputAnnexHash(InputSelector),
    /// Index of the current input (returned by `current_index` jet).
    CurrentInputIndex,

    // ── Output fields ──────────────────────────────────────────────────────
    /// Value (in satoshis) of an output.
    OutputValue(OutputSelector),
    /// Script hash of an output.
    OutputScriptHash(OutputSelector),

    // ── Aggregates ─────────────────────────────────────────────────────────
    /// Sum of all input values.
    TotalInputValue,
    /// Sum of all output values.
    TotalOutputValue,

    // ── Taproot / script context ───────────────────────────────────────────
    /// Taproot leaf version of this script.
    TapleafVersion,
    /// Taproot internal key.
    InternalKey,
    /// Taproot merkle path.
    Tappath,
    /// Commitment Merkle Root of this script.
    ScriptCmr,

    // ── Elements extensions ────────────────────────────────────────────────
    /// Genesis block hash (Elements global context).
    #[cfg(feature = "elements")]
    GenesisBlockHash,
    /// The LBTC asset ID.
    #[cfg(feature = "elements")]
    LbtcAsset,
    /// Confidential asset of an input.
    #[cfg(feature = "elements")]
    InputAsset(InputSelector),
    /// Confidential amount of an input.
    #[cfg(feature = "elements")]
    InputAmount(InputSelector),
    /// Pegin flag of an input.
    #[cfg(feature = "elements")]
    InputPegin(InputSelector),
    /// Script hash of an input's UTxO.
    #[cfg(feature = "elements")]
    InputScriptHash(InputSelector),
    /// Asset amount from an issuance.
    #[cfg(feature = "elements")]
    IssuanceAssetAmount(InputSelector),
    /// Token amount from an issuance.
    #[cfg(feature = "elements")]
    IssuanceTokenAmount(InputSelector),
    /// Asset range proof from an issuance.
    #[cfg(feature = "elements")]
    IssuanceAssetProof(InputSelector),
    /// Token range proof from an issuance.
    #[cfg(feature = "elements")]
    IssuanceTokenProof(InputSelector),
    /// Entropy of an issuance (also used to derive asset/token IDs).
    #[cfg(feature = "elements")]
    IssuanceEntropy(InputSelector),
    /// Whether an issuance exists for an input.
    #[cfg(feature = "elements")]
    IssuancePresent(InputSelector),
    /// New issuance contract for an input.
    #[cfg(feature = "elements")]
    NewIssuanceContract(InputSelector),
    /// Reissuance blinding factor for an input.
    #[cfg(feature = "elements")]
    ReissuanceBlinding(InputSelector),
    /// Reissuance entropy for an input.
    #[cfg(feature = "elements")]
    ReissuanceEntropy(InputSelector),
    /// Confidential asset of an output.
    #[cfg(feature = "elements")]
    OutputAsset(OutputSelector),
    /// Confidential amount of an output.
    #[cfg(feature = "elements")]
    OutputAmount(OutputSelector),
    /// Nonce of an output.
    #[cfg(feature = "elements")]
    OutputNonce(OutputSelector),
    /// Range proof of an output.
    #[cfg(feature = "elements")]
    OutputRangeProof(OutputSelector),
    /// Surjection proof of an output.
    #[cfg(feature = "elements")]
    OutputSurjectionProof(OutputSelector),
    /// Whether an output is a fee output.
    #[cfg(feature = "elements")]
    OutputIsFee(OutputSelector),
    /// Null datum of an output.
    #[cfg(feature = "elements")]
    OutputNullDatum(OutputSelector),
    /// Total fee in the transaction.
    #[cfg(feature = "elements")]
    TotalFee,
}

/// Combined effect summary for a Simplicity AST subtree.
///
/// Computed bottom-up during the annotation pass and attached to every node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectSummary {
    /// All transaction fields read anywhere in this subtree.
    pub reads: BTreeSet<TransactionField>,
    /// Whether any node in this subtree can cause script failure.
    pub can_fail: bool,
    /// True if this node's output type is `Unit` and the subtree has no side
    /// effects at all.  Such a subtree is observationally inert and can be
    /// replaced with a bare `Unit` node without changing program semantics.
    pub is_pure_unit: bool,
}

impl EffectSummary {
    /// An inert summary: no reads, cannot fail, is a pure unit.
    pub const fn pure_unit() -> Self {
        EffectSummary {
            reads: BTreeSet::new(),
            can_fail: false,
            is_pure_unit: true,
        }
    }

    /// A summary for a node that has no effects and does not return Unit.
    pub const fn none() -> Self {
        EffectSummary {
            reads: BTreeSet::new(),
            can_fail: false,
            is_pure_unit: false,
        }
    }

    /// Merge two summaries (union of reads, OR of can_fail).
    /// `is_pure_unit` is not propagated here — callers set it explicitly.
    pub fn merge(a: &Self, b: &Self) -> Self {
        EffectSummary {
            reads: a.reads.union(&b.reads).cloned().collect(),
            can_fail: a.can_fail || b.can_fail,
            is_pure_unit: false,
        }
    }
}

/// Annotate every node in a Simplicity program with its [`EffectSummary`].
///
/// Returns a `Vec` in post-order (index 0 = first leaf, last index = root).
/// Shared nodes (DAG sharing) are processed exactly once; child summaries are
/// looked up by their index in this `Vec`.
///
/// # Parameters
///
/// - `root`: root of the program DAG.
/// - `get_arrow`: closure that extracts the [`FinalArrow`] from the node's
///   cached data.  For [`CommitNode<J>`] pass `|d| d.arrow()`; for
///   [`RedeemNode<J>`] pass the same.
///
/// Prefer the convenience wrappers [`annotate_commit`] and [`annotate_redeem`]
/// where possible.
pub fn annotate_effects<N, F>(root: &Arc<Node<N>>, get_arrow: F) -> Vec<EffectSummary>
where
    N: Marker,
    N::Jet: Jet,
    F: Fn(&N::CachedData) -> &FinalArrow,
{
    use crate::dag::{DagLike, MaxSharing};
    use crate::node::Inner;

    let mut summaries: Vec<EffectSummary> = Vec::new();

    for item in (&**root).post_order_iter::<MaxSharing<N>>() {
        let node: &Node<N> = item.node;
        let arrow = get_arrow(node.cached_data());
        let target_is_unit = arrow.target.is_unit();

        // Pre-computed child summaries, available because children are always
        // processed before parents in post-order.
        let left = item.left_index.map(|i| &summaries[i]);
        let right = item.right_index.map(|i| &summaries[i]);

        let summary = match node.inner() {
            // ── Always fails ─────────────────────────────────────────────
            Inner::Fail(_) => EffectSummary {
                reads: BTreeSet::new(),
                can_fail: true,
                is_pure_unit: false,
            },

            // ── Jet: effects declared by the jet itself ───────────────────
            Inner::Jet(j) => {
                let reads: BTreeSet<TransactionField> = j.read_effects().into_iter().collect();
                let can_fail = j.has_write_effect();
                let is_pure_unit = target_is_unit && !can_fail && reads.is_empty();
                EffectSummary {
                    reads,
                    can_fail,
                    is_pure_unit,
                }
            }

            // ── Nullary pure nodes ────────────────────────────────────────
            Inner::Iden | Inner::Unit | Inner::Word(_) | Inner::Witness(_) => EffectSummary {
                reads: BTreeSet::new(),
                can_fail: false,
                is_pure_unit: target_is_unit,
            },

            // ── Unary transparent nodes ───────────────────────────────────
            Inner::InjL(_) | Inner::InjR(_) | Inner::Take(_) | Inner::Drop(_) => {
                let child = left.expect("unary node must have left child");
                let is_pure_unit = target_is_unit && !child.can_fail && child.reads.is_empty();
                EffectSummary {
                    reads: child.reads.clone(),
                    can_fail: child.can_fail,
                    is_pure_unit,
                }
            }

            // ── Assert: pruned branch always introduces a failure path ────
            // TODO: Confirm this.
            Inner::AssertL(_, _) | Inner::AssertR(_, _) => {
                let child = left.expect("assert node must have left child");
                EffectSummary {
                    reads: child.reads.clone(),
                    can_fail: true,
                    is_pure_unit: false,
                }
            }

            // ── Binary nodes: union of both children ──────────────────────
            Inner::Comp(_, _) | Inner::Case(_, _) | Inner::Pair(_, _) => {
                let l = left.expect("binary node must have left child");
                let r = right.expect("binary node must have right child");
                let mut merged = EffectSummary::merge(l, r);
                merged.is_pure_unit = target_is_unit && !merged.can_fail && merged.reads.is_empty();
                merged
            }

            // ── Disconnect: left always present, right optional ───────────
            Inner::Disconnect(_, _) => match (left, right) {
                (Some(l), Some(r)) => {
                    let mut merged = EffectSummary::merge(l, r);
                    merged.is_pure_unit =
                        target_is_unit && !merged.can_fail && merged.reads.is_empty();
                    merged
                }
                (Some(child), None) | (None, Some(child)) => {
                    let is_pure_unit = target_is_unit && !child.can_fail && child.reads.is_empty();
                    EffectSummary {
                        reads: child.reads.clone(),
                        can_fail: child.can_fail,
                        is_pure_unit,
                    }
                }
                (None, None) => EffectSummary {
                    reads: BTreeSet::new(),
                    can_fail: false,
                    is_pure_unit: target_is_unit,
                },
            },
        };

        summaries.push(summary);
    }

    summaries
}

/// Annotate a [`CommitNode`] program with effect summaries.
///
/// Returns a `Vec` in post-order; the last element is the root summary.
/// See [`annotate_effects`] for details.
pub fn annotate_commit<J: Jet>(root: &Arc<CommitNode<J>>) -> Vec<EffectSummary> {
    annotate_effects(root, |data| data.arrow())
}

/// Annotate a [`RedeemNode`] program with effect summaries.
///
/// Returns a `Vec` in post-order; the last element is the root summary.
/// See [`annotate_effects`] for details.
pub fn annotate_redeem<J: Jet>(root: &Arc<RedeemNode<J>>) -> Vec<EffectSummary> {
    annotate_effects(root, |data| data.arrow())
}

/// Which arm of a branch node was taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchArm {
    Left,
    Right,
}

// ─────────────────────────────────────────────────────────────────────────────
// Analysis 2: Transaction field coverage (malleability)
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a malleability analysis.
///
/// Produced by [`malleability_analysis`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalleabilityReport {
    /// Transaction fields read by the program.  Changes to these fields would
    /// invalidate the script.
    pub covered: BTreeSet<TransactionField>,
    /// Transaction fields **not** read by the program.  A third party can
    /// modify these fields without invalidating the script — they are the
    /// malleability surface.
    pub uncovered: BTreeSet<TransactionField>,
}

/// Analyse which transaction fields are not committed to by the program.
///
/// Any field in `uncovered` can be modified by a third party without
/// invalidating the script, representing a potential malleability vector.
///
/// Pass the `summaries` Vec returned by [`annotate_effects`] and a `universe`
/// of all fields that should be considered.  Use [`TransactionField::all`] for
/// Bitcoin programs or [`TransactionField::all_elements`] for Elements programs.
pub fn malleability_analysis(
    summaries: &[EffectSummary],
    universe: &BTreeSet<TransactionField>,
) -> MalleabilityReport {
    // The root summary (last element) already contains the union of all reads.
    let covered = summaries
        .last()
        .map(|s| s.reads.clone())
        .unwrap_or_default();
    let uncovered = universe.difference(&covered).cloned().collect();
    MalleabilityReport { covered, uncovered }
}

// ─────────────────────────────────────────────────────────────────────────────
// Analysis 3: Unit-type pruning
// ─────────────────────────────────────────────────────────────────────────────

/// A node that is safe to replace with a bare `unit` combinator.
///
/// The node's subtree has return type `Unit` and no side effects whatsoever,
/// so it is observationally inert.  Produced by [`pruneable_nodes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneableNode {
    /// Index of the node in the post-order summary `Vec`.
    pub node_index: usize,
}

/// Identify all subtree roots that can be replaced with a bare `unit` node.
///
/// A node is pruneable when its [`EffectSummary::is_pure_unit`] flag is set.
/// That flag is `true` iff the node's target type is `Unit`, `can_fail` is
/// `false`, and `reads` is empty — meaning the entire subtree is
/// observationally inert.
///
/// The returned `Vec` is in post-order.  For a top-down pruning pass, process
/// from largest index to smallest; once a subtree root is pruned, its children
/// do not need to be visited separately.
///
/// # Note on structural rewriting
///
/// Actually replacing the identified subtrees with `unit` combinators in a
/// `CommitNode` or `RedeemNode` requires reconstructing parent nodes with
/// updated type arrows.  That reconstruction depends on the `Context`
/// lifetime used during program construction and is deferred to a later
/// implementation step.
pub fn pruneable_nodes(summaries: &[EffectSummary]) -> Vec<PruneableNode> {
    summaries
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_pure_unit)
        .map(|(i, _)| PruneableNode { node_index: i })
        .collect()
}

/// Optimize a [`CommitNode`] by replacing pure-unit subtrees with bare `unit`
/// nodes.
///
/// A pure-unit subtree is one whose target type is `Unit`, has no failure
/// effects (`can_fail` is false), and reads no transaction fields. Such
/// subtrees are observationally inert and can be safely replaced with `unit`.
///
/// Returns the optimized program and the number of nodes that were replaced.
pub fn optimize_pure_unit<J: Jet>(root: &Arc<CommitNode<J>>) -> (Arc<CommitNode<J>>, usize) {
    let summaries = annotate_commit(root);
    let all_pruneable: HashSet<usize> = summaries
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_pure_unit)
        .map(|(i, _)| i)
        .collect();

    if all_pruneable.is_empty() {
        return (Arc::clone(root), 0);
    }

    // Compute the set of top-level pruneable nodes: those that are pruneable
    // but not subsumed by a larger pruneable parent. Also exclude bare `unit`
    // nodes since replacing those is a no-op.
    let mut subsumed: HashSet<usize> = HashSet::new();
    let mut bare_units: HashSet<usize> = HashSet::new();
    for item in root.as_ref().post_order_iter::<MaxSharing<Commit<J>>>() {
        if all_pruneable.contains(&item.index) {
            // Mark children as subsumed.
            if let Some(l) = item.left_index {
                subsumed.insert(l);
            }
            if let Some(r) = item.right_index {
                subsumed.insert(r);
            }
        }
        if matches!(item.node.inner(), Inner::Unit) {
            bare_units.insert(item.index);
        }
    }
    let top_level: HashSet<usize> = all_pruneable
        .iter()
        .copied()
        .filter(|i| !subsumed.contains(i) && !bare_units.contains(i))
        .collect();

    if top_level.is_empty() {
        return (Arc::clone(root), 0);
    }

    let mut replaced = 0usize;
    let mut rebuilt: Vec<Arc<CommitNode<J>>> = Vec::new();

    for item in root.as_ref().post_order_iter::<MaxSharing<Commit<J>>>() {
        if top_level.contains(&item.index) {
            // This subtree is a top-level pure unit — replace with a bare `unit` node.
            // Preserve the original arrow (source → Unit).
            let orig_arrow = item.node.cached_data().arrow().clone();
            let unit_inner: Inner<
                &Arc<CommitData<J>>,
                J,
                &crate::node::NoDisconnect,
                &crate::node::NoWitness,
            > = Inner::Unit;
            let data = CommitData::from_final(orig_arrow, unit_inner);
            rebuilt.push(Arc::new(Node::from_parts(Inner::Unit, Arc::new(data))));
            replaced += 1;
        } else {
            // Reconstruct the node with (possibly optimized) children.
            let new_inner = item.node.inner().clone().map_left_right(
                |_| Arc::clone(&rebuilt[item.left_index.unwrap()]),
                |_| Arc::clone(&rebuilt[item.right_index.unwrap()]),
            );
            // Map children to their cached data for CommitData::from_final.
            let data_inner = new_inner.as_ref().map(|node| node.cached_data());
            let new_data =
                CommitData::from_final(item.node.cached_data().arrow().clone(), data_inner);
            rebuilt.push(Arc::new(Node::from_parts(new_inner, Arc::new(new_data))));
        }
    }

    (rebuilt.pop().unwrap(), replaced)
}

// ─────────────────────────────────────────────────────────────────────────────
// Analysis 4: Per-code-path enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// A single executable code path through the program, determined by branch
/// choices at `case` nodes.
#[derive(Debug, Clone)]
pub struct CodePath {
    /// Case-node choices that define this path.
    /// Each entry is (MaxSharing post-order index, which arm was taken).
    pub choices: Vec<(usize, BranchArm)>,
    /// Transaction fields read along this path.
    pub reads: BTreeSet<TransactionField>,
    /// Whether this path can fail (has a write/failure effect).
    pub can_fail: bool,
}

/// Enumerate all possible execution paths through a [`CommitNode`] program.
///
/// At each `case` node the analysis forks into two paths (left arm, right arm).
/// For sequential combinators (`comp`, `pair`) the child paths are combined via
/// cross-product.  Returns one [`CodePath`] per distinct execution path.
///
/// If the number of paths exceeds `max_paths`, enumeration stops early and the
/// second return value is `true`.
pub fn enumerate_code_paths<J: Jet>(
    root: &Arc<CommitNode<J>>,
    max_paths: usize,
) -> (Vec<CodePath>, bool) {
    use crate::dag::{DagLike, MaxSharing};
    use crate::node::{Commit, Inner};
    use std::collections::HashMap;

    // Build pointer → MaxSharing post-order index map.
    let mut sids: HashMap<usize, usize> = HashMap::new();
    for item in root.as_ref().post_order_iter::<MaxSharing<Commit<J>>>() {
        sids.insert(item.node as *const _ as usize, item.index);
    }

    fn walk<J: Jet>(
        node: &CommitNode<J>,
        sids: &HashMap<usize, usize>,
        max: usize,
    ) -> (Vec<CodePath>, bool) {
        let ptr = node as *const _ as usize;
        let sid = sids.get(&ptr).copied().unwrap_or(0);

        match node.inner() {
            // Leaves
            Inner::Unit | Inner::Iden | Inner::Witness(_) | Inner::Word(_) => (
                vec![CodePath {
                    choices: vec![],
                    reads: BTreeSet::new(),
                    can_fail: false,
                }],
                false,
            ),
            Inner::Fail(_) => (
                vec![CodePath {
                    choices: vec![],
                    reads: BTreeSet::new(),
                    can_fail: true,
                }],
                false,
            ),
            Inner::Jet(j) => {
                let reads = j.read_effects().into_iter().collect();
                let can_fail = j.has_write_effect();
                (
                    vec![CodePath {
                        choices: vec![],
                        reads,
                        can_fail,
                    }],
                    false,
                )
            }

            // Unary: inherit child paths
            Inner::InjL(c) | Inner::InjR(c) | Inner::Take(c) | Inner::Drop(c) => walk(c, sids, max),
            Inner::AssertL(c, _) => {
                let (mut paths, tr) = walk(c, sids, max);
                for p in &mut paths {
                    p.can_fail = true;
                }
                (paths, tr)
            }
            Inner::AssertR(_, c) => {
                let (mut paths, tr) = walk(c, sids, max);
                for p in &mut paths {
                    p.can_fail = true;
                }
                (paths, tr)
            }

            // Case: fork into left and right paths
            Inner::Case(l, r) => {
                let (mut lp, lt) = walk(l, sids, max);
                let (mut rp, rt) = walk(r, sids, max);
                for p in &mut lp {
                    p.choices.insert(0, (sid, BranchArm::Left));
                }
                for p in &mut rp {
                    p.choices.insert(0, (sid, BranchArm::Right));
                }
                lp.extend(rp);
                let truncated = lt || rt || lp.len() > max;
                if lp.len() > max {
                    lp.truncate(max);
                }
                (lp, truncated)
            }

            // Binary sequential: cross-product of child paths
            Inner::Comp(l, r) | Inner::Pair(l, r) => {
                let (lp, lt) = walk(l, sids, max);
                let (rp, rt) = walk(r, sids, max);
                let mut result = Vec::new();
                let mut truncated = lt || rt;
                'outer: for left in &lp {
                    for right in &rp {
                        if result.len() >= max {
                            truncated = true;
                            break 'outer;
                        }
                        let mut choices = left.choices.clone();
                        choices.extend(right.choices.iter().cloned());
                        let reads = left.reads.union(&right.reads).cloned().collect();
                        let can_fail = left.can_fail || right.can_fail;
                        result.push(CodePath {
                            choices,
                            reads,
                            can_fail,
                        });
                    }
                }
                (result, truncated)
            }

            // Disconnect: only left child exists at commit time
            Inner::Disconnect(l, _) => walk(l, sids, max),
        }
    }

    walk(root, &sids, max_paths)
}

impl fmt::Display for InputSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputSelector::Current => f.write_str("current_input"),
            InputSelector::Indexed => f.write_str("indexed_input"),
            InputSelector::All => f.write_str("all_inputs"),
        }
    }
}

impl fmt::Display for OutputSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputSelector::Indexed => f.write_str("indexed_output"),
            OutputSelector::All => f.write_str("all_outputs"),
        }
    }
}

impl fmt::Display for TransactionField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionField::Version => f.write_str("version"),
            TransactionField::Locktime => f.write_str("locktime"),
            TransactionField::InputCount => f.write_str("input_count"),
            TransactionField::OutputCount => f.write_str("output_count"),
            TransactionField::InputPrevOutpoint(sel) => write!(f, "{}.prev_outpoint", sel),
            TransactionField::InputSequence(sel) => write!(f, "{}.sequence", sel),
            TransactionField::InputValue(sel) => write!(f, "{}.value", sel),
            TransactionField::InputScriptSigHash(sel) => write!(f, "{}.script_sig_hash", sel),
            TransactionField::InputAnnexHash(sel) => write!(f, "{}.annex_hash", sel),
            TransactionField::CurrentInputIndex => f.write_str("current_input.index"),
            TransactionField::OutputValue(sel) => write!(f, "{}.value", sel),
            TransactionField::OutputScriptHash(sel) => write!(f, "{}.script_hash", sel),
            TransactionField::TotalInputValue => f.write_str("total_input_value"),
            TransactionField::TotalOutputValue => f.write_str("total_output_value"),
            TransactionField::TapleafVersion => f.write_str("tapleaf_version"),
            TransactionField::InternalKey => f.write_str("internal_key"),
            TransactionField::Tappath => f.write_str("tappath"),
            TransactionField::ScriptCmr => f.write_str("script_cmr"),
            #[cfg(feature = "elements")]
            TransactionField::GenesisBlockHash => f.write_str("genesis_block_hash"),
            #[cfg(feature = "elements")]
            TransactionField::LbtcAsset => f.write_str("lbtc_asset"),
            #[cfg(feature = "elements")]
            TransactionField::InputAsset(sel) => write!(f, "{}.asset", sel),
            #[cfg(feature = "elements")]
            TransactionField::InputAmount(sel) => write!(f, "{}.amount", sel),
            #[cfg(feature = "elements")]
            TransactionField::InputPegin(sel) => write!(f, "{}.pegin", sel),
            #[cfg(feature = "elements")]
            TransactionField::InputScriptHash(sel) => write!(f, "{}.script_hash", sel),
            #[cfg(feature = "elements")]
            TransactionField::IssuanceAssetAmount(sel) => {
                write!(f, "{}.issuance_asset_amount", sel)
            }
            #[cfg(feature = "elements")]
            TransactionField::IssuanceTokenAmount(sel) => {
                write!(f, "{}.issuance_token_amount", sel)
            }
            #[cfg(feature = "elements")]
            TransactionField::IssuanceAssetProof(sel) => {
                write!(f, "{}.issuance_asset_proof", sel)
            }
            #[cfg(feature = "elements")]
            TransactionField::IssuanceTokenProof(sel) => {
                write!(f, "{}.issuance_token_proof", sel)
            }
            #[cfg(feature = "elements")]
            TransactionField::IssuanceEntropy(sel) => write!(f, "{}.issuance_entropy", sel),
            #[cfg(feature = "elements")]
            TransactionField::IssuancePresent(sel) => write!(f, "{}.issuance_present", sel),
            #[cfg(feature = "elements")]
            TransactionField::NewIssuanceContract(sel) => {
                write!(f, "{}.new_issuance_contract", sel)
            }
            #[cfg(feature = "elements")]
            TransactionField::ReissuanceBlinding(sel) => {
                write!(f, "{}.reissuance_blinding", sel)
            }
            #[cfg(feature = "elements")]
            TransactionField::ReissuanceEntropy(sel) => write!(f, "{}.reissuance_entropy", sel),
            #[cfg(feature = "elements")]
            TransactionField::OutputAsset(sel) => write!(f, "{}.asset", sel),
            #[cfg(feature = "elements")]
            TransactionField::OutputAmount(sel) => write!(f, "{}.amount", sel),
            #[cfg(feature = "elements")]
            TransactionField::OutputNonce(sel) => write!(f, "{}.nonce", sel),
            #[cfg(feature = "elements")]
            TransactionField::OutputRangeProof(sel) => write!(f, "{}.range_proof", sel),
            #[cfg(feature = "elements")]
            TransactionField::OutputSurjectionProof(sel) => {
                write!(f, "{}.surjection_proof", sel)
            }
            #[cfg(feature = "elements")]
            TransactionField::OutputIsFee(sel) => write!(f, "{}.is_fee", sel),
            #[cfg(feature = "elements")]
            TransactionField::OutputNullDatum(sel) => write!(f, "{}.null_datum", sel),
            #[cfg(feature = "elements")]
            TransactionField::TotalFee => f.write_str("total_fee"),
        }
    }
}

impl TransactionField {
    pub fn all_bitcoin() -> BTreeSet<TransactionField> {
        todo!("Not supported at this time.")
        // These should be verified before use.
        //  use InputSelector::All as AllIn;
        // use OutputSelector::All as AllOut;
        // let mut fields = vec![];
        // fields.extend([
        //     TransactionField::Version,
        //     TransactionField::Locktime,
        //     TransactionField::InputPrevOutpoint(AllIn),
        //     TransactionField::InputSequence(AllIn),
        //     TransactionField::InputAnnexHash(AllIn),
        //     TransactionField::OutputAmount(AllOut),
        //     TransactionField::OutputNonce(AllOut),
        //     TransactionField::OutputScriptHash(AllOut),
        //     TransactionField::InputAmount(AllIn),
        //     TransactionField::InputScriptHash(AllIn),
        //     // Tap env hash
        //     TransactionField::TapleafVersion,
        //     TransactionField::ScriptCmr,
        //     TransactionField::Tappath,
        //     TransactionField::InternalKey,
        //     TransactionField::CurrentInputIndex,
        // ]);
        // fields.into_iter().collect()
    }

    #[cfg(feature = "elements")]
    pub fn all_elements() -> BTreeSet<TransactionField> {
        use InputSelector::All as AllIn;
        use OutputSelector::All as AllOut;
        // let mut fields = Self::all_bitcoin();
        let mut fields = vec![];
        fields.extend([
            TransactionField::GenesisBlockHash,
            TransactionField::Version,
            TransactionField::Locktime,
            // TransactionField::LbtcAsset,
            TransactionField::InputPrevOutpoint(AllIn),
            TransactionField::InputPegin(AllIn),
            // TransactionField::InputAsset(Current),
            // TransactionField::InputAsset(Indexed),
            TransactionField::InputSequence(AllIn),
            TransactionField::InputAnnexHash(AllIn),
            TransactionField::OutputAmount(AllOut),
            TransactionField::OutputAsset(AllOut),
            TransactionField::OutputNonce(AllOut),
            TransactionField::OutputScriptHash(AllOut),
            TransactionField::OutputRangeProof(AllOut),
            TransactionField::IssuancePresent(AllIn),
            TransactionField::IssuanceAssetAmount(AllIn),
            TransactionField::IssuanceTokenAmount(AllIn),
            TransactionField::IssuanceTokenProof(AllIn),
            TransactionField::IssuanceAssetProof(AllIn),
            TransactionField::IssuancePresent(AllIn),
            TransactionField::ReissuanceBlinding(AllIn),
            TransactionField::NewIssuanceContract(AllIn),
            TransactionField::IssuanceEntropy(AllIn),
            TransactionField::ReissuanceEntropy(AllIn),
            TransactionField::OutputSurjectionProof(AllOut),
            TransactionField::InputAsset(AllIn),
            TransactionField::InputAmount(AllIn),
            TransactionField::InputScriptHash(AllIn),
            // Tap env hash
            TransactionField::TapleafVersion,
            TransactionField::ScriptCmr,
            TransactionField::Tappath,
            TransactionField::InternalKey,
            TransactionField::CurrentInputIndex,
        ]);
        fields.into_iter().collect()
    }
}
