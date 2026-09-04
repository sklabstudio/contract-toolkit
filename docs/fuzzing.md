# Fuzzing

See `testing.md`. Reproducibility contract: every fuzz result records
`{target, seed, runs, failures, counterexample, tool, tool_version,
reproducible}`. Forge runs pass `--fuzz-seed` when a non-zero seed is given.

# Invariants

Explicit invariants only. Discovery order:

1. `forge test --match-test invariant` when forge is installed.
2. `invariants.yaml` / `invariants.json` explicit specs.
3. `function invariant_*` declarations in Solidity sources.

Without a runner, verdicts are `INCONCLUSIVE` — never invented.
