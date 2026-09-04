# Testing

- `sklab-contract test <path>` — forge/hardhat with normalized
  total/passed/failed/skipped/duration/failures; raw output preserved.
- `sklab-contract coverage <path>` — normalized line/branch/function/statement.
  Coverage is not a security proof.

# Fuzzing

- `sklab-contract fuzz <path> [--runs N] [--seed S]` — forge fuzz or Echidna
  adapter when installed; records seed/runs/failures/counterexample/tool version.
- Fixture `tests/fixtures/fuzz_math` exercises the deterministic setup.

# Invariants

- `sklab-contract invariants <path>` — forge invariant tests + Echidna
  properties where available; explicit/user-provided/public-standard templates
  only (`invariant_*` discovery + `invariants.yaml`).
- Public templates: ERC-20 conservation / unauthorized-mint-fails;
  ERC-4626 preview/deposit/withdraw rounding relationships — encoded only with
  documented assumptions. No automatic invariant mining (private boundary).
