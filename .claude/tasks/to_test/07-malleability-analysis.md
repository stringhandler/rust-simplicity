# Task: Implement transaction field coverage (malleability) analysis

## Summary

Using the annotated AST from task 05, implement a pass that collects the union of all transaction fields read by the entire program and reports any fields that are not covered — these represent the malleability surface.

## Details

The analysis:

1. Collect `reads` from the root node's `EffectSummary` (the union is already propagated bottom-up).
2. Compare against `TransactionField::all()` — a static list of all known fields.
3. Return the uncovered fields as the malleability surface.

```rust
pub struct MalleabilityReport {
    /// Fields read by the program — changes to these would invalidate the script.
    pub covered: BTreeSet<TransactionField>,
    /// Fields NOT read — a third party can change these without invalidating the script.
    pub uncovered: BTreeSet<TransactionField>,
}

pub fn malleability_analysis<J: Jet>(
    program: &AnnotatedProgram<J>,
) -> MalleabilityReport;
```

Add a `TransactionField::all() -> &'static [TransactionField]` associated function that returns every possible field (Bitcoin and Elements variants).

### Interpretation Notes to Document

- `uncovered` fields are malleable: a third party can modify them and the script will still pass.
- If a program uses `sig_all_hash` (or equivalent), `covered` should be the full set and `uncovered` should be empty.
- A program that only checks a single input's value will have a large `uncovered` set.
- The annex fields (`InputAnnexHash`) are worth calling out explicitly — if uncovered, the annex is freely modifiable.

## Acceptance Criteria

- A program using `sig_all_hash` produces an empty `uncovered` set.
- A minimal program (e.g. only checks `CurrentValue`) produces a large `uncovered` set containing all other fields.
- `TransactionField::all()` is exhaustive — adding a new variant to the enum causes a compile error until `all()` is updated.
