# Invariants

See `testing.md` / `fuzzing.md` for the full contract.

# Upgrades

- `sklab-contract upgrade-review <old> <new>` → SAFE / RISKY / INCOMPATIBLE /
  INCONCLUSIVE with evidence (proxy pattern, admin, initializer, storage,
  inheritance/authorization changes).
- `sklab-contract storage <path>` extracts normalized layouts
  (slot/offset/type/label/contract) from solc metadata, Foundry/Hardhat
  artifacts, or deterministic source heuristics.
- `sklab-contract storage-diff <old> <new>` diffs deterministically.
- `sklab-contract abi-diff <old> <new>` reports added/removed functions,
  selector changes, events, errors, mutability changes + `breaking` flag.
- Dogfood: `upgrade_v1` → `upgrade_v2` yields INCOMPATIBLE (inserted `admin`
  shifts `owner` slot) with exact evidence.

# Local forks

- `sklab-contract fork create [--chain X] [--block N]` prepares a local Anvil
  fork config: chain id, block, redacted RPC source, Anvil version.
- Safety: binds `127.0.0.1` only; `broadcast: false` always; RPC secrets come
  from env vars (`chains.<chain>.rpc_url_env`) and are redacted in output.
