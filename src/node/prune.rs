// SPDX-License-Identifier: CC0-1.0

//! Pruning of redeem programs
//!
//! See [`RedeemNode::prune`] for how a program is pruned.

use std::sync::Arc;

use crate::bit_machine::{ExecutionError, PruneTracker};
use crate::dag::{InternalSharing, MaxSharing, PostOrderIterItem};
use crate::jet::JetEnvironment;
use crate::types;
use crate::{BitMachine, Value};

use super::{
    Construct, ConstructData, ConstructNode, Constructible, Converter, Hide, Inner, Redeem,
    RedeemData, RedeemNode,
};

/// Prunes `program`, as described in [`RedeemNode::prune`].
pub(super) fn prune<JE: JetEnvironment, T: PruneTracker>(
    program: &RedeemNode,
    env: &JE,
    tracker: &mut T,
) -> Result<Arc<RedeemNode>, ExecutionError> {
    // 1) Merge nodes with equal IHRs. The IHR covers the source and target types of a
    // node but not the types inside it, so nodes with equal IHRs can contain case
    // nodes with different IHRs, which the tracker would mark separately, while the
    // encoding of the pruned program has a single node for all of them.
    let program = reduce_to_max_sharing(program);

    // 2) Run the Bit Machine and mark (un)used branches.
    // This is the only fallible step in the pruning process.
    let mut mac = BitMachine::for_program(&program)?;
    mac.exec_with_tracker(&program, env, tracker)?;

    // 3) Prune out unused case branches.
    // Because the types of the pruned program may change,
    // we construct a temporary witness program with unfinalized types.
    // Convert with `MaxSharing`: the tracker keys branch usage by IHR, so
    // converting IHR-equal nodes separately makes each copy keep the branches
    // that only its twins executed.
    types::Context::with_context(|inference_context| {
        let pruned_witness_program = program
            .convert::<MaxSharing<Redeem>, _, _>(&mut Pruner {
                inference_context,
                tracker,
            })
            .expect("pruning unused branches is infallible");

        // 4) Finalize the types of the witness program.
        // We obtain the pruned redeem program.
        // Once the pruned type is finalized, we can proceed to prune witness values.
        Ok(pruned_witness_program
            .convert::<InternalSharing, _, _>(&mut Finalizer)
            .expect("finalization is infallible"))
    })
}

fn reduce_to_max_sharing(program: &RedeemNode) -> Arc<RedeemNode> {
    program
        .convert::<MaxSharing<Redeem>, _, _>(&mut Identity)
        .expect("copying a program is infallible")
}

/// Converts a redeem program into a copy of itself. Converting with [`MaxSharing`]
/// gives a copy with a single node for each IHR, as in the program's encoding.
struct Identity;

impl Converter<Redeem, Redeem> for Identity {
    type Error = std::convert::Infallible;

    fn convert_witness(
        &mut self,
        _: &PostOrderIterItem<&RedeemNode>,
        witness: &Value,
    ) -> Result<Value, Self::Error> {
        Ok(witness.shallow_clone())
    }

    fn convert_disconnect(
        &mut self,
        _: &PostOrderIterItem<&RedeemNode>,
        right: Option<&Arc<RedeemNode>>,
        _: &Arc<RedeemNode>,
    ) -> Result<Arc<RedeemNode>, Self::Error> {
        Ok(Arc::clone(right.expect(
            "disconnect node in redeem program has a right child",
        )))
    }

    fn convert_data(
        &mut self,
        data: &PostOrderIterItem<&RedeemNode>,
        inner: Inner<&Arc<RedeemNode>, &Arc<RedeemNode>, &Value>,
    ) -> Result<Arc<RedeemData>, Self::Error> {
        let converted_inner = inner
            .map(|node| node.cached_data())
            .map_disconnect(|node| node.cached_data())
            .map_witness(Value::shallow_clone);
        Ok(Arc::new(RedeemData::new(
            data.node.arrow().shallow_clone(),
            converted_inner,
        )))
    }
}

struct Pruner<'brand, 't, T> {
    inference_context: types::Context<'brand>,
    tracker: &'t mut T,
}

impl<'brand, 't, T> Converter<Redeem, Construct<'brand>> for Pruner<'brand, 't, T>
where
    T: PruneTracker,
{
    type Error = std::convert::Infallible;

    fn convert_witness(
        &mut self,
        _: &PostOrderIterItem<&RedeemNode>,
        witness: &Value,
    ) -> Result<Option<Value>, Self::Error> {
        // The pruned type is not finalized at this point,
        // so we cannot prune the witness value.
        Ok(Some(witness.shallow_clone()))
    }

    fn convert_disconnect(
        &mut self,
        _: &PostOrderIterItem<&RedeemNode>,
        right: Option<&Arc<ConstructNode<'brand>>>,
        _: &Arc<RedeemNode>,
    ) -> Result<Option<Arc<ConstructNode<'brand>>>, Self::Error> {
        debug_assert!(
            right.is_some(),
            "disconnected branch should exist in unpruned redeem program"
        );
        Ok(right.map(Arc::clone))
    }

    fn prune_case(
        &mut self,
        data: &PostOrderIterItem<&RedeemNode>,
        _left: &Arc<ConstructNode>,
        _right: &Arc<ConstructNode>,
    ) -> Result<Hide, Self::Error> {
        // The IHR of the pruned program may change,
        // but the Converter trait gives us access to the unpruned node (`data`).
        // The Bit Machine tracked (un)used case branches based on the unpruned IHR.
        match (
            self.tracker.contains_left(data.node.ihr()),
            self.tracker.contains_right(data.node.ihr()),
        ) {
            (true, true) => Ok(Hide::Neither),
            (false, true) => Ok(Hide::Left),
            (true, false) => Ok(Hide::Right),
            (false, false) => Ok(Hide::Neither), // case nodes that were never executed will be pruned out by their ancestors
        }
    }

    fn convert_data(
        &mut self,
        _: &PostOrderIterItem<&RedeemNode>,
        inner: Inner<
            &Arc<ConstructNode<'brand>>,
            &Option<Arc<ConstructNode<'brand>>>,
            &Option<Value>,
        >,
    ) -> Result<ConstructData<'brand>, Self::Error> {
        let converted_inner = inner
            .map(|node| node.cached_data())
            .map_witness(Option::<Value>::clone);
        let retyped = ConstructData::from_inner(&self.inference_context, converted_inner)
            .expect("pruned types should check out if unpruned types check out");
        Ok(retyped)
    }
}

struct Finalizer;

impl<'brand> Converter<Construct<'brand>, Redeem> for Finalizer {
    type Error = std::convert::Infallible;

    fn convert_witness(
        &mut self,
        data: &PostOrderIterItem<&ConstructNode>,
        witness: &Option<Value>,
    ) -> Result<Value, Self::Error> {
        let pruned_target_ty = data
            .node
            .arrow()
            .target
            .finalize()
            .expect("pruned types should check out if unpruned types check out");
        let pruned_witness = witness
            .as_ref()
            .expect("witness node that originally stems from redeem program should be populated")
            .prune(&pruned_target_ty)
            .expect("pruned type should be shrunken version of unpruned type");
        Ok(pruned_witness)
    }

    fn convert_disconnect(
        &mut self,
        _: &PostOrderIterItem<&ConstructNode>,
        right: Option<&Arc<RedeemNode>>,
        _: &Option<Arc<ConstructNode>>,
    ) -> Result<Arc<RedeemNode>, Self::Error> {
        Ok(right.map(Arc::clone).expect(
            "disconnect node that originally stems from redeem program should have all branches",
        ))
    }

    fn convert_data(
        &mut self,
        data: &PostOrderIterItem<&ConstructNode>,
        inner: Inner<&Arc<RedeemNode>, &Arc<RedeemNode>, &Value>,
    ) -> Result<Arc<RedeemData>, Self::Error> {
        // Finalize target types of witness nodes in advance so we can prune their values.
        let final_arrow = data
            .node
            .arrow()
            .finalize()
            .expect("pruned types should check out if unpruned types check out");
        let converted_inner = inner
            .map(|node| node.cached_data())
            .map_disconnect(|node| node.cached_data())
            .map_witness(Value::shallow_clone);
        Ok(Arc::new(RedeemData::new(final_arrow, converted_inner)))
    }
}
