# Task: Implement effect methods for Elements jets

## Summary

Implement `read_effects` and `has_write_effect` for every Elements jet variant in `src/jet/init/elements.rs`. Elements is a superset of Bitcoin jets with additional confidential transaction fields.

## Details

Elements jets include all Bitcoin jets plus extensions for:
- Confidential assets and amounts (`InputAsset`, `InputAmount`, `OutputAsset`, etc.)
- Issuance fields (`InputIssuanceAssetAmount`, `InputIssuanceTokenAmount`, etc.)
- Reissuance fields (`InputReissuanceBlinding`, `InputReissuanceEntropy`)
- Peg-in (`InputPegin`)
- Extended output fields (`OutputNonce`, `OutputSurjectionProof`, etc.)
- Fee (`TotalFee`)

Additional high-level hash jets (e.g. `InputsHash`, `OutputsHash`, `InputUtxosHash`) implicitly cover large sets of fields — denormalize these fully into their constituent `TransactionField` primitives.

For each variant, return the correct static slice and `has_write_effect` bool. Follow the same exhaustive `match` pattern used for Bitcoin jets in task 03.

## Acceptance Criteria

- Every Elements jet variant has an explicit implementation.
- Tests cover at least: one confidential asset jet, one issuance jet, one hash-aggregation jet (checking the denormalized field list is complete).
