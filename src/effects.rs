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

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use crate::jet::Jet;
use crate::node::{CommitNode, Marker, Node, RedeemNode};
use crate::types::arrow::FinalArrow;

/// Selects which input a field refers to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InputSelector {
    /// The current input (the one being spent).
    Current,
    /// Any input, selected by index at runtime.
    Any,
}

/// Selects which output a field refers to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OutputSelector {
    /// Any output, selected by index at runtime.
    Any,
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
                EffectSummary { reads, can_fail, is_pure_unit }
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
                let is_pure_unit =
                    target_is_unit && !child.can_fail && child.reads.is_empty();
                EffectSummary {
                    reads: child.reads.clone(),
                    can_fail: child.can_fail,
                    is_pure_unit,
                }
            }

            // ── Assert: pruned branch always introduces a failure path ────
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
                merged.is_pure_unit =
                    target_is_unit && !merged.can_fail && merged.reads.is_empty();
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
                    let is_pure_unit =
                        target_is_unit && !child.can_fail && child.reads.is_empty();
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

// ─────────────────────────────────────────────────────────────────────────────
// Analysis 1: Missing write effects
// ─────────────────────────────────────────────────────────────────────────────

/// Which arm of a branch node is missing a write effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchArm {
    Left,
    Right,
}

/// A branch node whose arm has no write effect (cannot fail).
///
/// Produced by [`missing_write_effects`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingWriteEffect {
    /// Index of the `Case` or `Assert` node in the post-order summary Vec.
    pub node_index: usize,
    /// Which arm is missing a write effect.
    pub arm: BranchArm,
    /// Whether the arm is also a pure unit (completely inert).
    pub is_pure_unit: bool,
}

/// Find all branch arms that have no write side effect.
///
/// A branch with `can_fail == false` can be taken without the script ever
/// failing, meaning the program enforces no constraint on that path.  This
/// is almost always a policy error.
///
/// Pass the `summaries` Vec returned by [`annotate_effects`] (or the
/// convenience wrappers) together with the original `root` so that the
/// node's `Inner` variant can be inspected.
pub fn missing_write_effects<N>(
    root: &Arc<Node<N>>,
    summaries: &[EffectSummary],
) -> Vec<MissingWriteEffect>
where
    N: Marker,
    N::Jet: Jet,
{
    use crate::dag::{DagLike, MaxSharing};
    use crate::node::Inner;

    let mut results = Vec::new();

    for item in (&**root).post_order_iter::<MaxSharing<N>>() {
        let node: &Node<N> = item.node;
        let idx = item.index;

        match node.inner() {
            Inner::Case(_, _) => {
                let left_idx = item.left_index.expect("Case must have left child");
                let right_idx = item.right_index.expect("Case must have right child");
                let left_s = &summaries[left_idx];
                let right_s = &summaries[right_idx];

                if !left_s.can_fail {
                    results.push(MissingWriteEffect {
                        node_index: idx,
                        arm: BranchArm::Left,
                        is_pure_unit: left_s.is_pure_unit,
                    });
                }
                if !right_s.can_fail {
                    results.push(MissingWriteEffect {
                        node_index: idx,
                        arm: BranchArm::Right,
                        is_pure_unit: right_s.is_pure_unit,
                    });
                }
            }
            // AssertL keeps left child; right branch is pruned (always fails by construction).
            Inner::AssertL(_, _) => {
                let left_idx = item.left_index.expect("AssertL must have left child");
                let left_s = &summaries[left_idx];
                if !left_s.can_fail {
                    results.push(MissingWriteEffect {
                        node_index: idx,
                        arm: BranchArm::Left,
                        is_pure_unit: left_s.is_pure_unit,
                    });
                }
            }
            // AssertR keeps right child (stored as left in the DAG traversal).
            Inner::AssertR(_, _) => {
                let child_idx = item.left_index.expect("AssertR must have child");
                let child_s = &summaries[child_idx];
                if !child_s.can_fail {
                    results.push(MissingWriteEffect {
                        node_index: idx,
                        arm: BranchArm::Right,
                        is_pure_unit: child_s.is_pure_unit,
                    });
                }
            }
            _ => {}
        }
    }

    results
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

impl fmt::Display for TransactionField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InputSelector::{Any, Current};
        use OutputSelector::Any as AnyOut;
        match self {
            TransactionField::Version => f.write_str("version"),
            TransactionField::Locktime => f.write_str("locktime"),
            TransactionField::InputCount => f.write_str("input_count"),
            TransactionField::OutputCount => f.write_str("output_count"),
            TransactionField::InputPrevOutpoint(Current) => f.write_str("current_input.prev_outpoint"),
            TransactionField::InputPrevOutpoint(Any) => f.write_str("any_input.prev_outpoint"),
            TransactionField::InputSequence(Current) => f.write_str("current_input.sequence"),
            TransactionField::InputSequence(Any) => f.write_str("any_input.sequence"),
            TransactionField::InputValue(Current) => f.write_str("current_input.value"),
            TransactionField::InputValue(Any) => f.write_str("any_input.value"),
            TransactionField::InputScriptSigHash(Current) => f.write_str("current_input.script_sig_hash"),
            TransactionField::InputScriptSigHash(Any) => f.write_str("any_input.script_sig_hash"),
            TransactionField::InputAnnexHash(Current) => f.write_str("current_input.annex_hash"),
            TransactionField::InputAnnexHash(Any) => f.write_str("any_input.annex_hash"),
            TransactionField::CurrentInputIndex => f.write_str("current_input.index"),
            TransactionField::OutputValue(AnyOut) => f.write_str("any_output.value"),
            TransactionField::OutputScriptHash(AnyOut) => f.write_str("any_output.script_hash"),
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
            TransactionField::InputAsset(Current) => f.write_str("current_input.asset"),
            #[cfg(feature = "elements")]
            TransactionField::InputAsset(Any) => f.write_str("any_input.asset"),
            #[cfg(feature = "elements")]
            TransactionField::InputAmount(Current) => f.write_str("current_input.amount"),
            #[cfg(feature = "elements")]
            TransactionField::InputAmount(Any) => f.write_str("any_input.amount"),
            #[cfg(feature = "elements")]
            TransactionField::InputPegin(Current) => f.write_str("current_input.pegin"),
            #[cfg(feature = "elements")]
            TransactionField::InputPegin(Any) => f.write_str("any_input.pegin"),
            #[cfg(feature = "elements")]
            TransactionField::InputScriptHash(Current) => f.write_str("current_input.script_hash"),
            #[cfg(feature = "elements")]
            TransactionField::InputScriptHash(Any) => f.write_str("any_input.script_hash"),
            #[cfg(feature = "elements")]
            TransactionField::IssuanceAssetAmount(Current) => f.write_str("current_input.issuance_asset_amount"),
            #[cfg(feature = "elements")]
            TransactionField::IssuanceAssetAmount(Any) => f.write_str("any_input.issuance_asset_amount"),
            #[cfg(feature = "elements")]
            TransactionField::IssuanceTokenAmount(Current) => f.write_str("current_input.issuance_token_amount"),
            #[cfg(feature = "elements")]
            TransactionField::IssuanceTokenAmount(Any) => f.write_str("any_input.issuance_token_amount"),
            #[cfg(feature = "elements")]
            TransactionField::IssuanceAssetProof(Current) => f.write_str("current_input.issuance_asset_proof"),
            #[cfg(feature = "elements")]
            TransactionField::IssuanceAssetProof(Any) => f.write_str("any_input.issuance_asset_proof"),
            #[cfg(feature = "elements")]
            TransactionField::IssuanceTokenProof(Current) => f.write_str("current_input.issuance_token_proof"),
            #[cfg(feature = "elements")]
            TransactionField::IssuanceTokenProof(Any) => f.write_str("any_input.issuance_token_proof"),
            #[cfg(feature = "elements")]
            TransactionField::IssuanceEntropy(Current) => f.write_str("current_input.issuance_entropy"),
            #[cfg(feature = "elements")]
            TransactionField::IssuanceEntropy(Any) => f.write_str("any_input.issuance_entropy"),
            #[cfg(feature = "elements")]
            TransactionField::IssuancePresent(Current) => f.write_str("current_input.issuance_present"),
            #[cfg(feature = "elements")]
            TransactionField::IssuancePresent(Any) => f.write_str("any_input.issuance_present"),
            #[cfg(feature = "elements")]
            TransactionField::NewIssuanceContract(Current) => f.write_str("current_input.new_issuance_contract"),
            #[cfg(feature = "elements")]
            TransactionField::NewIssuanceContract(Any) => f.write_str("any_input.new_issuance_contract"),
            #[cfg(feature = "elements")]
            TransactionField::ReissuanceBlinding(Current) => f.write_str("current_input.reissuance_blinding"),
            #[cfg(feature = "elements")]
            TransactionField::ReissuanceBlinding(Any) => f.write_str("any_input.reissuance_blinding"),
            #[cfg(feature = "elements")]
            TransactionField::ReissuanceEntropy(Current) => f.write_str("current_input.reissuance_entropy"),
            #[cfg(feature = "elements")]
            TransactionField::ReissuanceEntropy(Any) => f.write_str("any_input.reissuance_entropy"),
            #[cfg(feature = "elements")]
            TransactionField::OutputAsset(AnyOut) => f.write_str("any_output.asset"),
            #[cfg(feature = "elements")]
            TransactionField::OutputAmount(AnyOut) => f.write_str("any_output.amount"),
            #[cfg(feature = "elements")]
            TransactionField::OutputNonce(AnyOut) => f.write_str("any_output.nonce"),
            #[cfg(feature = "elements")]
            TransactionField::OutputRangeProof(AnyOut) => f.write_str("any_output.range_proof"),
            #[cfg(feature = "elements")]
            TransactionField::OutputSurjectionProof(AnyOut) => f.write_str("any_output.surjection_proof"),
            #[cfg(feature = "elements")]
            TransactionField::OutputIsFee(AnyOut) => f.write_str("any_output.is_fee"),
            #[cfg(feature = "elements")]
            TransactionField::OutputNullDatum(AnyOut) => f.write_str("any_output.null_datum"),
            #[cfg(feature = "elements")]
            TransactionField::TotalFee => f.write_str("total_fee"),
        }
    }
}

impl TransactionField {
    /// All Bitcoin transaction fields (no Elements extensions).
    pub fn all_bitcoin() -> BTreeSet<TransactionField> {
        use InputSelector::{Any, Current};
        use OutputSelector::Any as AnyOut;
        [
            TransactionField::Version,
            TransactionField::Locktime,
            TransactionField::InputCount,
            TransactionField::OutputCount,
            TransactionField::InputPrevOutpoint(Current),
            TransactionField::InputPrevOutpoint(Any),
            TransactionField::InputSequence(Current),
            TransactionField::InputSequence(Any),
            TransactionField::InputValue(Current),
            TransactionField::InputValue(Any),
            TransactionField::InputScriptSigHash(Current),
            TransactionField::InputScriptSigHash(Any),
            TransactionField::InputAnnexHash(Current),
            TransactionField::InputAnnexHash(Any),
            TransactionField::CurrentInputIndex,
            TransactionField::OutputValue(AnyOut),
            TransactionField::OutputScriptHash(AnyOut),
            TransactionField::TotalInputValue,
            TransactionField::TotalOutputValue,
            TransactionField::TapleafVersion,
            TransactionField::InternalKey,
            TransactionField::Tappath,
            TransactionField::ScriptCmr,
        ]
        .into_iter()
        .collect()
    }

    /// All Elements transaction fields (superset of Bitcoin).
    #[cfg(feature = "elements")]
    pub fn all_elements() -> BTreeSet<TransactionField> {
        use InputSelector::{Any, Current};
        use OutputSelector::Any as AnyOut;
        let mut fields = Self::all_bitcoin();
        fields.extend([
            TransactionField::GenesisBlockHash,
            TransactionField::LbtcAsset,
            TransactionField::InputAsset(Current),
            TransactionField::InputAsset(Any),
            TransactionField::InputAmount(Current),
            TransactionField::InputAmount(Any),
            TransactionField::InputPegin(Current),
            TransactionField::InputPegin(Any),
            TransactionField::InputScriptHash(Current),
            TransactionField::InputScriptHash(Any),
            TransactionField::IssuanceAssetAmount(Current),
            TransactionField::IssuanceAssetAmount(Any),
            TransactionField::IssuanceTokenAmount(Current),
            TransactionField::IssuanceTokenAmount(Any),
            TransactionField::IssuanceAssetProof(Current),
            TransactionField::IssuanceAssetProof(Any),
            TransactionField::IssuanceTokenProof(Current),
            TransactionField::IssuanceTokenProof(Any),
            TransactionField::IssuanceEntropy(Current),
            TransactionField::IssuanceEntropy(Any),
            TransactionField::IssuancePresent(Current),
            TransactionField::IssuancePresent(Any),
            TransactionField::NewIssuanceContract(Current),
            TransactionField::NewIssuanceContract(Any),
            TransactionField::ReissuanceBlinding(Current),
            TransactionField::ReissuanceBlinding(Any),
            TransactionField::ReissuanceEntropy(Current),
            TransactionField::ReissuanceEntropy(Any),
            TransactionField::OutputAsset(AnyOut),
            TransactionField::OutputAmount(AnyOut),
            TransactionField::OutputNonce(AnyOut),
            TransactionField::OutputRangeProof(AnyOut),
            TransactionField::OutputSurjectionProof(AnyOut),
            TransactionField::OutputIsFee(AnyOut),
            TransactionField::OutputNullDatum(AnyOut),
            TransactionField::TotalFee,
        ]);
        fields
    }
}
