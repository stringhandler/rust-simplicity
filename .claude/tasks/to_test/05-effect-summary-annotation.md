# Task: Build the `EffectSummary` struct and bottom-up annotation pass

## Summary

Define `EffectSummary` and implement a bottom-up tree walk that annotates every node in a Simplicity program with its combined effect summary.

## Details

Define:

```rust
pub struct EffectSummary {
    /// All transaction fields read by this subtree (union over all jets in subtree).
    pub reads: BTreeSet<TransactionField>,
    /// Whether any node in this subtree can cause script failure.
    pub can_fail: bool,
    /// True if this node's return type is Unit and the subtree has no effects at all.
    /// Such a subtree is observationally inert and can be replaced with a bare Unit node.
    pub is_pure_unit: bool,
}
```

Implement the annotation pass following the same bottom-up pattern as `src/analysis.rs` (cost analysis):

| Node | `reads` | `can_fail` | `is_pure_unit` |
|------|---------|-----------|----------------|
| `Jet(j)` | `j.read_effects()` | `j.has_write_effect()` | `false` |
| `Fail(_)` | `{}` | `true` | `false` |
| `Unit` | `{}` | `false` | `true` |
| `Iden`, `Word`, `Witness` | `{}` | `false` | `return_type == Unit` |
| `Comp(s, t)` | `s.reads ∪ t.reads` | `s.can_fail \|\| t.can_fail` | `return_type == Unit && !can_fail && reads.is_empty()` |
| `Case(l, r)` | `l.reads ∪ r.reads` | `l.can_fail \|\| r.can_fail` | `false` (branches computed independently) |
| `AssertL(c, _)` / `AssertR(_, c)` | `c.reads` | `true` (assertion always introduces a failure path) | `false` |
| `Pair(l, r)` | `l.reads ∪ r.reads` | `l.can_fail \|\| r.can_fail` | `false` (Pair never returns Unit) |
| `InjL(c)`, `InjR(c)`, `Take(c)`, `Drop(c)` | `c.reads` | `c.can_fail` | `return_type == Unit && !c.can_fail && c.reads.is_empty()` |

The annotated structure should store one `EffectSummary` per node, accessible via the same node handle used elsewhere in the codebase.

## Acceptance Criteria

- `EffectSummary` is computed for a full program without panics.
- A test program containing a mix of jets, `Fail`, and `Case` nodes produces correct summaries at each node.
- The pass does not re-traverse already-visited nodes (DAG sharing is respected).
