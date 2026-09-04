"""Slither adapter: version detect, safe run, machine-readable parse, normalize."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from sklab_contract_toolkit.core.pathsafety import resolve_root
from sklab_contract_toolkit.core.subprocess import run_tool
from sklab_contract_toolkit.models.findings import ContractFinding

_SEVERITY_MAP = {
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Informational": "INFO",
    "Optimization": "INFO",
}
_CONFIDENCE_MAP = {"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"}


def slither_available() -> bool:
    return shutil.which("slither") is not None


def slither_version() -> str:
    exe = shutil.which("slither")
    if not exe:
        return ""
    result = run_tool([exe, "--version"], cwd=Path.cwd(), timeout=30)
    out = (result.stdout + " " + result.stderr).strip().splitlines()
    return out[0].strip()[:120] if out and out[0].strip() else ""


def run_slither(root: Path | str, timeout: int = 300) -> dict[str, Any]:
    root_path = resolve_root(root)
    exe = shutil.which("slither")
    if not exe:
        return {"available": False, "findings": [], "notes": "Slither not installed; report honestly as unavailable."}
    result = run_tool([exe, ".", "--json", "-", "--disable-color"], cwd=root_path, timeout=timeout)
    findings = parse_slither_json(result.stdout)
    return {
        "available": True,
        "version": slither_version(),
        "findings": findings,
        "raw_output": (result.stdout + result.stderr)[:20000],
        "returncode": result.returncode,
        "timed_out": result.timed_out,
    }


def parse_slither_json(output: str) -> list[ContractFinding]:
    try:
        data = json.loads(output) if output.strip() else {}
    except json.JSONDecodeError:
        return []
    detectors = data.get("results", {}).get("detectors", []) if isinstance(data, dict) else []
    findings: list[ContractFinding] = []
    for item in detectors:
        if not isinstance(item, dict):
            continue
        check = str(item.get("check", "unknown"))
        impact = str(item.get("impact", "Informational"))
        confidence = str(item.get("confidence", "Medium"))
        elements = item.get("elements", []) or []
        contract = function = source_file = ""
        line = 0
        if elements and isinstance(elements[0], dict):
            el = elements[0]
            contract = str(el.get("type", "") or "")
            source = el.get("source_mapping", {}) or {}
            source_file = str(source.get("filename_relative", "") or source.get("filename_absolute", "") or "")
            try:
                line = int(source.get("lines", [0])[0]) if source.get("lines") else 0
            except (ValueError, TypeError, IndexError):
                line = 0
        description = str(item.get("description", ""))[:2000]
        findings.append(
            ContractFinding(
                rule_id=f"SLITHER-{check}",
                rule_version="1.0.0",
                title=check.replace("-", " ").replace("_", " "),
                category="CUSTOM",
                severity=_SEVERITY_MAP.get(impact, "INFO"),  # type: ignore[arg-type]
                confidence=_CONFIDENCE_MAP.get(confidence, "MEDIUM"),  # type: ignore[arg-type]
                evidence_level="TOOL_REPORTED",
                contract=contract,
                function=function,
                file=source_file,
                line=line,
                description=description,
                evidence=description,
                tool="slither",
                tool_rule=check,
                recommendation="See Slither detector documentation for remediation.",
            ).with_fingerprint()
        )
    return findings
