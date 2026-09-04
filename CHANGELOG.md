# Changelog

## 0.1.0 — 2026-09-04

Initial public release of SKLab Contract Toolkit.

- EVM / Solidity chain adapter (FULL)
- Toolchain manager: solc, Foundry/forge, Anvil, Hardhat, Slither + optional
  Echidna, Mythril, Halmos, Aderyn, Solhint adapters
- Project detection: Foundry, Hardhat, raw Solidity, mixed workspace,
  Truffle legacy
- Normalized contract inventory, semantic contract model, ABI extraction
- Authority / permission extraction (Ownable, AccessControl, custom roles)
- Standards registry: ERC-20/721/1155/165/2612/4626/2771/2981/4337,
  EIP-1967, UUPS, Transparent/Beacon proxies, Ownable, AccessControl, Pausable
- Contract category classification
- Structural graphs: inheritance, import, call, dependency, external-call,
  authority (JSON / DOT / Mermaid)
- compile / test / fuzz / invariants orchestration with normalized output
- Public standard invariant templates (ERC-20, ERC-4626)
- Internal deterministic static rules (versioned rule IDs)
- Slither adapter with finding normalization + dedupe
- Upgrade review, storage layout extraction/diff, ABI diff
- Bytecode / ABI-only inspection with SOURCE_UNAVAILABLE labeling
- Read-only contract-address inspection (no transactions)
- Local Anvil fork preparation (127.0.0.1 only, no broadcast)
- Project scaffolding: token, nft, vault, staking, custom
- Tokenomics / config arithmetic review helpers
- Gas review, coverage normalization
- Threat-model template population
- Evidence graph linking
- Remediation patch workflow + verification states
- Reports: Markdown / JSON / SARIF with stable fingerprints
- ReproBox / PatchBench / Orchestrator / Skill Hub integrations
- Public Contract Skill Pack (15 skills)
- Plugin architecture for ChainAdapter / ToolAdapter / Analyzer /
  Reporter / SkillProvider
