# Integrations

See `remediation.md` for ReproBox / PatchBench / Orchestrator / Skill Hub.

# Extension API

See `remediation.md`. Minimal analyzer plugin:

```python
from sklab_contract_toolkit.analysis.rules import Rule, _register
from sklab_contract_toolkit.models.findings import ContractFinding

def _check(model, rel, source):
    return []  # emit ContractFinding items with .with_fingerprint()

_register(Rule("MYORG-001", "1.0.0", "my check", "CUSTOM",
               "LOW", "MEDIUM", "desc", "rec", check=_check))
```

# Security

- No telemetry, no uploads, no wallet/RPC discovery.
- Local-only (`--local-only`) and offline (`--offline`) modes.
- Safe subprocess: argv arrays, explicit cwd, timeouts, bounded output,
  filtered env; `shell=True` is forbidden (tested).
- Path safety: project-root confinement, traversal/symlink/root-scan rejection
  (tested).
- Private-key safety: never read wallets/seeds, never sign, never print keys;
  deployment templates use `$PRIVATE_KEY` placeholders only; broadcast is
  impossible by construction (tested).
- RPC: env-var references only (`chains.<id>.rpc_url_env`); secret-bearing
  URLs redacted; never printed whole.
- Honesty: unavailable tools report `unavailable`; future chains report
  EXPERIMENTAL/UNAVAILABLE; bytecode-only inputs are labeled
  SOURCE_UNAVAILABLE; findings separate severity/confidence/evidence level.

# Demo (3 minutes, no live chain/funds)

1. `sklab-contract inspect tests/fixtures/erc20_flawed --json` — ERC-20 + owner graph.
2. `sklab-contract compile …` → success + fingerprint.
3. `sklab-contract test …` → normalized summary.
4. `sklab-contract analyze …` → access-control finding + authority evidence.
5. `sklab-contract fuzz …` / `invariants …` → runs recorded.
6. `sklab-contract fix <id> --out /tmp/fix` → patch (source untouched).
7. PatchBench/ReproBox hooks assess + pin the environment.
8. Apply fix → `sklab-contract verify <id>` → FIXED_VERIFIED.
9. `sklab-contract report … --out report` → MD/JSON/SARIF.
