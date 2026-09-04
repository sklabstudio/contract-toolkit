# Contract Model (public, deterministic)

`src/sklab_contract_toolkit/models/contract.py`: `ContractModel` with
contract_name, source_file, language, compiler_version, interfaces,
libraries, inheritance, functions, events, errors, state_variables,
modifiers, imports, external_dependencies — plus roles, external calls,
asset/upgrade references, dependencies, standards, category, authorities.

This is practical extracted fact — not a proprietary semantic engine.
Selectors use dependency-free Keccak-256 (`detection/solidity.py`).

# Standards

`standards/registry.py` detects ERC-20/721/1155/165/2612/4626/2771/2981/4337,
EIP-1967, UUPS, Transparent/Beacon proxies, Ownable, AccessControl, Pausable
via selectors + inheritance + source patterns + ABI, each with confidence.

`standards/categories.py` classifies TOKEN/NFT/VAULT/STAKING/VESTING/AIRDROP/
PRESALE/ESCROW/MARKETPLACE/TREASURY/GOVERNANCE/TIMELOCK/FACTORY/PROXY/
ORACLE_INTEGRATION/AMM/LENDING/REWARD_DISTRIBUTOR/PAYMENT/CUSTOM to aid
workflow selection.

# Findings

`models/findings.py`: `ContractFinding` with id, rule_id (+rule_version),
title, category, severity (INFO/LOW/MEDIUM/HIGH/CRITICAL), confidence
(LOW/MEDIUM/HIGH, kept separate), status, contract/function/file/line,
description, evidence, CWE/SWC, tool/tool_rule, recommendation, fingerprint.

Categories cover access control, reentrancy, external calls, signatures,
replay, arithmetic, rounding, token accounting, upgradeability, storage,
initialization, oracles, frontrunning/MEV, DoS, gas, events, authority,
delegatecall, selfdestruct, tx.origin, unchecked returns, approvals,
configuration, test coverage, custom.

Evidence levels: CONFIRMED / HEURISTIC / TOOL_REPORTED / INCONCLUSIVE.
