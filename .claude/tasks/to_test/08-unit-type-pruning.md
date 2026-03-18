# Task: Implement unit-type pruning optimisation

## Summary

Using the annotated AST from task 05, implement a pass that replaces any subtree whose return type is `Unit` and has no side effects with a bare `Unit` node, simplifying the program without changing its semantics.

## Details

The pruning rule: if a node's `EffectSummary` has `is_pure_unit == true`, the entire subtree rooted at that node can be replaced with `Unit`.

```rust
pub fn prune_pure_units<J: Jet>(
    program: AnnotatedProgram<J>,
) -> Program<J>;
```

Walk the annotated tree top-down (or bottom-up — bottom-up is simpler). At each node, if `is_pure_unit` is true, emit a `Unit` node in its place and do not recurse into its children.

### Interaction with Branch Analysis

Before pruning, the caller should run `missing_write_effects` (task 06) and present the results to the user. Branches that are `is_pure_unit == true` will be pruned away — this is irreversible. The user should be aware that these branches had no observable purpose.

### Edge Cases

- A `Case` node where one arm is `is_pure_unit` but the other is not: prune only the pure-unit arm, keep the other.
- A `Case` node where both arms are `is_pure_unit`: the entire `Case` is itself `is_pure_unit` and is pruned at the `Case` level.
- Do not prune `Fail` nodes even if their return type is `Unit` — `can_fail == true` prevents `is_pure_unit` from being set, so this should not arise.

## Acceptance Criteria

- A program with a no-op `Unit`-returning subtree (no jets, no fails) is reduced to a single `Unit` node for that subtree.
- A program with a meaningful subtree (has jets or can fail) is not modified.
- The output program is valid and passes existing type-checking.
- Test covers a `Case` where only one arm is prunable.

## Implementation Status

**Partially implemented.** The analysis/identification portion is done in `src/effects.rs`:

```rust
pub struct PruneableNode {
    pub node_index: usize,
}

pub fn pruneable_nodes(summaries: &[EffectSummary]) -> Vec<PruneableNode> {
    summaries
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_pure_unit)
        .map(|(i, _)| PruneableNode { node_index: i })
        .collect()
}
```

**Deferred:** The structural rewrite (actually replacing subtrees in the program tree with `Unit`) is deferred. The Simplicity node type system makes this complex:
- `RedeemData::new` requires `Inner<&Arc<Self>, J, &Arc<Self>, Value>` making out-of-band construction difficult
- `CommitNode` requires a type-inference `Context<'brand>` lifetime
- The `Converter` pattern from `node/convert.rs` can't change a node's `inner` type

**To test:** Call `pruneable_nodes()` on the result of `annotate_effects()` and verify the correct node indices are returned for known programs.
