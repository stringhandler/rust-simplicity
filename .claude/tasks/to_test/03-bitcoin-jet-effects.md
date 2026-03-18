# Task: Implement effect methods for Bitcoin jets

## Summary

Implement `read_effects` and `has_write_effect` for every Bitcoin jet variant in `src/jet/init/bitcoin.rs`.

## Details

For each variant in the Bitcoin jet enum, return the correct static slice of `TransactionField` values and the correct `has_write_effect` bool.

Examples:

| Jet | `read_effects` | `has_write_effect` |
|-----|---------------|-------------------|
| `Version` | `[TransactionField::Version]` | `false` |
| `LockTime` | `[TransactionField::Locktime]` | `false` |
| `InputPrevOutpoint` | `[TransactionField::InputPrevOutpoint(Any)]` | `false` |
| `CurrentPrevOutpoint` | `[TransactionField::InputPrevOutpoint(Current)]` | `false` |
| `CurrentValue` | `[TransactionField::InputValue(Current)]` | `false` |
| `NumInputs` | `[TransactionField::InputCount]` | `false` |
| `NumOutputs` | `[TransactionField::OutputCount]` | `false` |
| `CheckSigVerify` | `[TransactionField::InputAnnexHash(Current), ...]` (sighash fields) | `true` |
| `CheckLockTime` | `[TransactionField::Locktime]` | `true` |
| `CheckLockHeight` | `[TransactionField::Locktime]` | `true` |
| `CheckLockDuration` | `[TransactionField::InputSequence(Current)]` | `true` |
| `CheckLockDistance` | `[TransactionField::InputSequence(Current)]` | `true` |
| Pure arithmetic/hash jets | `[]` | `false` |

For jets that compute a hash over many fields (e.g. any sighash-related jet), denormalize the full set of primitive fields covered by that hash.

## Acceptance Criteria

- Every Bitcoin jet variant has an explicit `read_effects` and `has_write_effect` implementation (no missed variants — use `match` exhaustively).
- Tests cover at least: one pure jet, one environment-reading jet, one verify jet.
