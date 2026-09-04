"""Internal analysis engine: run all versioned rules over a project."""

from __future__ import annotations

from pathlib import Path

from sklab_contract_toolkit.analysis.rules import RULES
from sklab_contract_toolkit.core.pathsafety import iter_project_files, resolve_root
from sklab_contract_toolkit.detection.solidity import parse_source_file
from sklab_contract_toolkit.models.findings import ContractFinding


def run_internal_analysis(root: Path | str) -> list[ContractFinding]:
    root_path = resolve_root(root)
    findings: list[ContractFinding] = []
    for path in iter_project_files(root_path, (".sol",)):
        try:
            rel = path.relative_to(root_path).as_posix()
        except ValueError:
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for model in parse_source_file(path, root_path):
            for rule in RULES.values():
                if rule.check is None:
                    continue
                try:
                    findings.extend(rule.check(model, rel, source) or [])
                except Exception:
                    continue
    # ensure fingerprints
    for f in findings:
        f.with_fingerprint()
    findings.sort(key=lambda x: (x.severity, x.rule_id, x.file, x.line))
    return findings


def list_rules() -> list[dict[str, str]]:
    return [
        {
            "rule_id": r.rule_id,
            "rule_version": r.rule_version,
            "title": r.title,
            "category": r.category,
            "severity": r.severity,
            "confidence": r.confidence,
        }
        for r in sorted(RULES.values(), key=lambda r: r.rule_id)
    ]
