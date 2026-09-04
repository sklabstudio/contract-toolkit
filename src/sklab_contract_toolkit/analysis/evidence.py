"""Evidence graph: link finding -> source -> tool output -> test ->
counterexample -> remediation -> verification. Open metadata plumbing.
"""

from __future__ import annotations

from typing import Any


def link_evidence(finding: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    ctx = context or {}
    return {
        "finding_id": finding.get("id"),
        "rule_id": finding.get("rule_id"),
        "source_location": f"{finding.get('file')}:{finding.get('line')}",
        "tool_output": finding.get("evidence", ""),
        "test": ctx.get("test", ""),
        "counterexample": ctx.get("counterexample", ""),
        "remediation": ctx.get("remediation", ""),
        "verification_result": ctx.get("verification_result", ""),
    }
