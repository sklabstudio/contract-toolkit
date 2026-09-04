# Architecture

```
Contract Source / Repo / ABI / Bytecode
            ↓
      Detect Chain / Project        (detection/, chains/registry.py)
            ↓
      Select Chain Adapter          (chains/: base, evm FULL, future stubs)
            ↓
     Select Toolchain Adapter       (tools/manager.py + adapters.py)
            ↓
        Inspect / Compile           (detection/solidity.py, testing/flows.py)
            ↓
   Static Analysis / Tests          (analysis/, testing/)
            ↓
      Fuzz / Invariants             (testing/flows.py)
            ↓
 Upgrade / Storage / Roles          (upgrades/, analysis/authorities.py)
            ↓
   Normalize Evidence/Findings      (models/findings.py)
            ↓
       Report / Verify              (reports/, analysis/remediation.py)
```

Design rules:

- Open tooling: every stage emits typed Pydantic models + machine-readable JSON.
- Portable adapters: `ChainAdapter` / `ToolAdapter` ABCs; future private systems
  plug in via `register_adapter()` without modifying public core.
- Reproducible analysis: stable SHA-256 fingerprints (no timestamps) over
  source + tool versions + config + ruleset.
- Evidence-backed findings: severity ≠ confidence ≠ evidence level; no
  exploitability claims without executed evidence.
- Safe engineering: local-only/offline modes, path confinement, safe
  subprocess (no `shell=True`), no keys, no broadcast.
