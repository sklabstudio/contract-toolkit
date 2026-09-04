"""Reproducible reports: Markdown / JSON / SARIF with stable fingerprints."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sklab_contract_toolkit.analysis.rules import RULESET_VERSION
from sklab_contract_toolkit.core.fingerprints import (
    fingerprint_mapping,
    scan_fingerprint,
    source_tree_fingerprint,
)
from sklab_contract_toolkit.core.pathsafety import resolve_root
from sklab_contract_toolkit.tools.manager import environment_metadata

SARIF_SEVERITY = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def build_report_bundle(
    root: Path | str,
    contracts: list[dict[str, Any]],
    standards: list[dict[str, Any]],
    authorities: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    tests: dict[str, Any] | None = None,
    fuzz: list[dict[str, Any]] | None = None,
    invariants: list[dict[str, Any]] | None = None,
    upgrade: dict[str, Any] | None = None,
    gas: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    project: dict[str, Any] | None = None,
    config_digest: str = "",
) -> dict[str, Any]:
    root_path = resolve_root(root)
    try:
        source_fp = source_tree_fingerprint(root_path)
    except Exception:
        source_fp = ""
    env = environment_metadata()
    tool_versions = dict(env.get("tools", {}))
    fingerprint = scan_fingerprint(
        source_fingerprint=source_fp,
        compiler=str((project or {}).get("toolchain", "auto")),
        compiler_version=str(tool_versions.get("solc") or tool_versions.get("forge") or ""),
        tool_versions=tool_versions,
        config_digest=config_digest or fingerprint_mapping({"default": True}),
        ruleset_version=RULESET_VERSION,
    )
    return {
        "schema": "sklab-contract-report/1",
        "project": project or {},
        "chain": (project or {}).get("chain", "evm"),
        "toolchain": (project or {}).get("toolchain", "auto"),
        "tool_versions": tool_versions,
        "compiler": (project or {}).get("toolchain", "auto"),
        "contracts": contracts,
        "standards_detected": standards,
        "authorities": authorities,
        "findings": findings,
        "tests": tests or {},
        "fuzz": fuzz or [],
        "invariants": invariants or [],
        "upgrade_review": upgrade or {},
        "gas": gas or {},
        "coverage": coverage or {},
        "ruleset_version": RULESET_VERSION,
        "scan_fingerprint": fingerprint,
        "source_fingerprint": source_fp,
        "limitations": [
            "Static rules are heuristic; confirm high-severity items manually.",
            "Source-unavailable inputs reduce certainty (labeled SOURCE_UNAVAILABLE).",
            "Coverage is not a security proof.",
            "No exploitability is claimed without executed evidence.",
        ],
    }


def render_markdown(bundle: dict[str, Any]) -> str:
    lines = [
        "# SKLab Contract Report",
        "",
        f"- Chain: {bundle.get('chain')}",
        f"- Toolchain: {bundle.get('toolchain')}",
        f"- Scan fingerprint: `{bundle.get('scan_fingerprint')}`",
        f"- Ruleset: {bundle.get('ruleset_version')}",
        "",
        "## Contracts",
        "",
    ]
    for c in bundle.get("contracts", []):
        lines.append(f"- **{c.get('contract_name')}** ({c.get('source_file')}) — {c.get('category', 'CUSTOM')}")
    lines += ["", "## Standards", ""]
    for s in bundle.get("standards_detected", []):
        lines.append(f"- {s.get('standard')}: {s.get('confidence')}")
    lines += ["", "## Authorities", ""]
    for a in bundle.get("authorities", []):
        lines.append(f"- {a.get('authority')} → {a.get('target_contract')}: {a.get('capability')}")
    lines += ["", "## Findings", ""]
    if not bundle.get("findings"):
        lines.append("No findings.")
    for f in bundle.get("findings", []):
        lines.append(f"### [{f.get('severity')}/{f.get('confidence')}] {f.get('title')} ({f.get('rule_id')})")
        lines.append(
            f"- Location: `{f.get('file')}:{f.get('line')}` contract={f.get('contract')} function={f.get('function')}"
        )
        if f.get("description"):
            lines.append(f"- {f.get('description')}")
        if f.get("evidence"):
            lines.append(f"- Evidence: {str(f.get('evidence'))[:400]}")
        if f.get("recommendation"):
            lines.append(f"- Recommendation: {f.get('recommendation')}")
        lines.append("")
    tests = bundle.get("tests", {})
    if tests:
        lines += [
            "## Tests",
            "",
            f"- total={tests.get('total')} passed={tests.get('passed')} "
            f"failed={tests.get('failed')} skipped={tests.get('skipped')} "
            f"tool={tests.get('tool')}",
            "",
        ]
    lines += ["## Limitations", ""]
    for item in bundle.get("limitations", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def render_sarif(bundle: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in bundle.get("findings", []):
        rule_id = str(f.get("rule_id", "UNKNOWN"))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": str(f.get("title", rule_id)),
                "helpUri": "https://github.com/sklabstudio/contract-toolkit",
                "properties": {"category": f.get("category"), "cwe": f.get("cwe"), "swc": f.get("swc")},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_SEVERITY.get(str(f.get("severity", "INFO")), "note"),
                "message": {"text": str(f.get("description", f.get("title")))[:1000]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(f.get("file", ""))},
                            "region": {"startLine": int(f.get("line", 0) or 1)},
                        }
                    }
                ],
                "properties": {
                    "confidence": f.get("confidence"),
                    "fingerprint": f.get("fingerprint"),
                    "tool": f.get("tool"),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "sklab-contract", "version": "0.1.0", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }


def write_reports(bundle: dict[str, Any], out_dir: Path | str) -> dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    md_path = out / "contract-report.md"
    json_path = out / "contract-report.json"
    sarif_path = out / "contract-report.sarif"
    md_path.write_text(render_markdown(bundle), encoding="utf-8")
    json_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    sarif_path.write_text(json.dumps(render_sarif(bundle), indent=2), encoding="utf-8")
    return {"markdown": str(md_path), "json": str(json_path), "sarif": str(sarif_path)}
