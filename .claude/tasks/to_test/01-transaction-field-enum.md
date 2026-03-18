# Task: Define `TransactionField` enum

## Summary

Create a `TransactionField` enum that represents all primitive transaction data points that jets can read from the environment. This is the foundation for all read-effect tracking.

## Details

Define in a new module (e.g. `src/analysis/effects.rs` or `src/effects.rs`):

```rust
pub enum TransactionField {
    Version,
    Locktime,
    InputCount,
    OutputCount,
    InputPrevOutpoint(InputSelector),
    InputSequence(InputSelector),
    InputValue(InputSelector),
    InputScriptSigHash(InputSelector),
    InputAnnexHash(InputSelector),
    OutputValue(OutputSelector),
    OutputScriptHash(OutputSelector),
    // Elements extensions:
    InputAsset(InputSelector),
    InputAmount(InputSelector),
    InputIssuanceAssetAmount(InputSelector),
    InputIssuanceTokenAmount(InputSelector),
    InputReissuanceBlinding(InputSelector),
    InputReissuanceEntropy(InputSelector),
    InputPegin(InputSelector),
    OutputAsset(OutputSelector),
    OutputNonce(OutputSelector),
    // ... add remaining Elements fields
}

pub enum InputSelector { Current, Any }
pub enum OutputSelector { Any }
```

- Derive `Debug`, `Clone`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Hash` so values can be stored in `BTreeSet`.
- Keep Bitcoin and Elements fields in the same enum — Elements is a superset.
- Document each variant with a comment referencing the jet(s) that read it.

## Acceptance Criteria

- Enum compiles and is usable in `BTreeSet<TransactionField>`.
- All Bitcoin jet environment reads are representable.
- All Elements jet environment reads are representable.
- No fields are missing that would prevent accurate effect tracking in later tasks.
