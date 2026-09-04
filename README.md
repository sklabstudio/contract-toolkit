# SKLab Contract Toolkit

**Open smart-contract engineering, testing, analysis, and verification infrastructure for the SKLab ecosystem.**

Build, inspect, test, analyze, and verify smart contracts across modern blockchain toolchains.

Quick start:

```bash
pip install sklab-contract-toolkit
sklab-contract inspect .
sklab-contract compile .
sklab-contract test .
sklab-contract analyze .
sklab-contract fuzz .
sklab-contract invariants .
```

## Why

Public contract work needs reproducible, portable, inspectable infrastructure —
not a black-box wrapper around one analyzer. This toolkit normalizes chains,
toolchains, findings, storage, and reports so humans and agents (Orchestrator,
Skill Hub) share one machine-readable contract.

## Architecture

See `docs/architecture.md`. Pipeline: detect → adapters → inspect/compile →
analysis/tests → fuzz/invariants → upgrade/storage/roles → normalize →
report/verify.

## Supported Chains

EVM / Solidity is **FULL** in v0.1.0. Solana, Move (Aptos/Sui), CosmWasm, TON
exist as honest `EXPERIMENTAL`/`UNAVAILABLE` stubs — never faked.

## Supported Toolchains

`sklab-contract tools` shows installed/version/status/capabilities per tool.
First-class: solc, Foundry/forge, Anvil, Hardhat, Slither. Optional when
installed: Echidna, Mythril, Halmos, Aderyn, Solhint. Missing tools degrade
honestly to labeled simulation (`sklab-sim`) — never fake tool output.

## Project Detection

Weighted evidence for Foundry (`foundry.toml`), Hardhat (`hardhat.config.*`),
raw Solidity, mixed workspaces, Truffle legacy.

## Contract Inspection

`sklab-contract inspect <path> [--json] [--abi F] [--bytecode F]` emits the
normalized inventory (functions/events/errors/state/modifiers/imports),
ABI with Keccak selectors, authority graph, standards with confidence, and
structural graphs (JSON/DOT/Mermaid). Bytecode/ABI-only inputs are labeled
`SOURCE_UNAVAILABLE` with reduced capabilities.

`sklab-contract inspect-address <chain> <address>` is read-only (code,
verified ABI, proxy slots). No transactions, no keys.

## Standards

ERC-20/721/1155/165/2612/4626/2771/2981/4337, EIP-1967, UUPS,
Transparent/Beacon proxies, Ownable, AccessControl, Pausable — plus category
classification (TOKEN/NFT/VAULT/…/CUSTOM).

## Authority Graph

Ownable, AccessControl, custom modifiers/roles, multisig/timelock references,
upgrade admin, pauser/minter/operator/governor — each with evidence + confidence.

## Static Analysis

`sklab-contract analyze <path> [--local-only] [--offline]` runs 15 versioned
internal rules plus Slither when available; findings normalize to
`ContractFinding` (severity ≠ confidence ≠ evidence level) and dedupe by
stable fingerprint.

## Testing / Fuzzing / Invariants

`test`, `fuzz --runs N --seed S`, `invariants` orchestrate forge/Hardhat/
Echidna with normalized, reproducible output. Public ERC-20/ERC-4626 invariant
templates ship with documented assumptions; no proprietary invariant mining.

## Upgrade Review / Storage Layout / ABI Diff

`upgrade-review <old> <new>` → SAFE/RISKY/INCOMPATIBLE/INCONCLUSIVE.
`storage` + `storage-diff` handle layouts; `abi-diff` flags breaking changes.

## Local Forks

`sklab-contract fork create` prepares Anvil configs bound to `127.0.0.1` with
`broadcast: false`. RPC via env vars only, redacted in output.

## Contract Scaffolding

`sklab-contract new <token|nft|vault|staking|custom> <dest>` — SKLab-authored
templates with stated assumptions, tests, README, deployment TEMPLATE
(no keys), verification checklist. Never auto-deploys.

## Remediation

`fix` returns isolated patches (source untouched, never pushed);
`verify` re-runs the pipeline → FIXED_VERIFIED/…/INCONCLUSIVE.
PatchBench/ReproBox hooks included.

## Reports

`sklab-contract report <path> --out DIR` writes `contract-report.md/.json/
.sarif` with stable scan fingerprints (no timestamps).

## Orchestrator / Skill Hub / ReproBox / PatchBench

Typed Python SDK (`ContractToolkit`) + machine-readable CLI JSON for
Orchestrator; 16-skill public Contract Pack with audited permissions;
ReproBox fingerprints; PatchBench verification. See `docs/remediation.md`.

## Extension API

`ChainAdapter` / `ToolAdapter` / `Analyzer` / `Reporter` / `SkillProvider`
with `register_adapter()` hooks — private systems extend without touching
public core. See `docs/extension-api.md`.

## Security Model

No telemetry, no keys, no signing, no broadcast, no `shell=True`, root-
confined paths, offline-capable. See `docs/security.md`.

## Limitations

- Heuristic static rules: confirm HIGH items manually.
- No exploitability claims without executed evidence.
- Non-EVM chains are stubs; advanced/symbolic tools are optional adapters.
- Coverage is not a security proof.

## Roadmap

Public: Solana/Anchor, Sui/Aptos Move, CosmWasm, TON adapters; richer
symbolic/formal adapters; plugin registry; richer SARIF; SBOM; reproducible
compiler images; on-chain metadata adapters; CI regression templates.
Private extensions (spec/invariant mining, economic simulation, exploit
regression, contagion modeling, continuous assurance) build on the public
extension hooks and are intentionally out of scope here.

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
mypy src
python -m build
```

## License

MIT © 2026 SKLab Studio. Third-party tools retain their own licenses.
