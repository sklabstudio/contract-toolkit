# Remediation

- `sklab-contract fix <finding-or-report> [--out DIR]` — generates a patch in
  an isolated workspace. Default returns the patch; never modifies the source
  repo directly unless explicitly requested; never pushes.
- `sklab-contract verify <finding-or-report>` — re-runs compile, relevant
  tests, analyzers, fuzz/invariants where applicable, plus PatchBench when
  available → FIXED_VERIFIED / FIXED_UNVERIFIED / NOT_FIXED / REGRESSION /
  INCONCLUSIVE.
- Evidence graph (`analysis/evidence.py`) links finding → source → tool output
  → test → counterexample → remediation → verification.

# Integrations

- **ReproBox**: pinned build environments, environment fingerprint recorded
  (`integrations/connectors.py::reprobox_info`).
- **PatchBench**: independent patch verification; scoring lives in PatchBench
  (`patchbench_verify`).
- **Orchestrator**: machine-readable actions inspect/compile/analyze/test/fuzz/
  invariants/upgrade-review/fix/verify — no autonomous orchestration inside
  this toolkit.
- **Skill Hub**: 16-skill public Contract Pack (`skills/data/*.yaml`), audited
  permissions (no secrets; network only for read-only address inspection).

# Extension API

Plugin contracts: `ChainAdapter`, `ToolAdapter`, `Analyzer` (rule callables),
`Reporter` (`reports/builder.py`), `SkillProvider` (`skills/pack.py`).

```python
from sklab_contract_toolkit.chains.registry import register_adapter
register_adapter("my-chain", MyAdapter())  # no public-core changes needed
```

Private SKLab systems extend via these hooks; proprietary logic
(semantic IR, invariant mining, economic twins, exploit replay, contagion,
blast-radius/assurance scoring, live monitoring, learning) is out of scope —
see `security.md`.
