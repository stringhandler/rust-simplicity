# Task: Implement missing-write-effects analysis

## Summary

Using the annotated AST from task 05, implement a pass that identifies branches which have no write side effects (i.e. cannot fail), flagging them as policy gaps.

## Details

Walk the annotated tree and inspect every `Case`, `AssertL`, and `AssertR` node. For each branch:

- If `can_fail == false`: the branch can be taken without any script failure — the script enforces no condition on this path.
- If additionally `is_pure_unit == true`: the branch is entirely inert and contributes nothing observable.

Produce a report type:

```rust
pub struct MissingWriteEffect {
    /// Position/identifier of the Case or Assert node
    pub node: NodeId,
    /// Which arm is missing a write effect (Left, Right, or the only child for Assert)
    pub arm: BranchArm,
    /// Whether the arm is also a pure unit (fully inert)
    pub is_pure_unit: bool,
}

pub enum BranchArm { Left, Right, Child }
```

The analysis function signature:

```rust
pub fn missing_write_effects<J: Jet>(
    program: &AnnotatedProgram<J>,
) -> Vec<MissingWriteEffect>;
```

## Acceptance Criteria

- Returns an empty `Vec` for a program where every branch has at least one verify jet or `Fail` node.
- Correctly identifies and reports branches with no write effects in a test program.
- Correctly distinguishes between a branch that merely has no write effect vs. one that is also a pure unit.
