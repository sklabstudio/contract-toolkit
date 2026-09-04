# Findings

- Internal rules: `analysis/rules.py` (15 versioned rules, `RULESET_VERSION=1.0.0`).
- Slither adapter: `analysis/slither_norm.py` — version detect, safe run,
  JSON parse, normalization (original detector ID preserved in `tool_rule`),
  dedupe with internal findings.
- Optional adapters (Mythril/Halmos) run bounded, locally, findings normalized;
  formal proof is never claimed unless tool semantics support it.
- `deduplicate_findings()` merges by fingerprint, keeping provenance.
- Rule semantics changes require a `rule_version` bump.
