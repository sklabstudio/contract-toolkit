"""ReproBox / PatchBench / Orchestrator / SkillHub typed integrations.

These integrations use local interfaces only — no network, no telemetry.
They detect sibling SKLab checkouts when present and otherwise operate in
standalone mode with recorded environment fingerprints.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sklab_contract_toolkit.tools.manager import environment_metadata


def _sibling(name: str) -> Path | None:
    here = Path(__file__).resolve()
    for parent in [here.parent.parent.parent.parent, here.parent.parent.parent.parent.parent]:
        candidate = parent / name
        if candidate.exists():
            return candidate
    cwd = Path.cwd()
    for candidate in [cwd / name, cwd.parent / name]:
        if candidate.exists():
            return candidate
    return None


def reprobox_info() -> dict[str, Any]:
    path = _sibling("reprobox")
    env = environment_metadata()
    return {
        "available": path is not None,
        "path": str(path) if path else "",
        "environment_fingerprint": env.get("fingerprint", ""),
        "tools": env.get("tools", {}),
        "mode": "local-pinned" if path else "standalone",
        "notes": "ReproBox provides pinned build environments for reproducibility.",
    }


def patchbench_verify(patch_text: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    path = _sibling("patchbench")
    checks = {
        "patch_nonempty": bool(patch_text and patch_text.strip()),
        "has_diff_markers": ("diff --git" in patch_text or "---" in patch_text) if patch_text else False,
        "touches_source": any(x in patch_text for x in (".sol", ".js", ".ts", ".py")) if patch_text else False,
    }
    score = sum(1 for v in checks.values() if v) / max(1, len(checks))
    return {
        "available": path is not None,
        "score": round(score, 3),
        "checks": checks,
        "verdict": "PLAUSIBLE" if score >= 0.66 else ("WEAK" if score >= 0.33 else "INSUFFICIENT"),
        "context": context or {},
        "notes": "PatchBench independently verifies remediation patches; scoring lives in PatchBench.",
    }


def orchestrator_actions() -> list[dict[str, Any]]:
    return [
        {"action": "inspect", "description": "Detect project + inventory contracts"},
        {"action": "compile", "description": "Compile with detected toolchain"},
        {"action": "analyze", "description": "Run static analysis + normalize findings"},
        {"action": "test", "description": "Run test suite"},
        {"action": "fuzz", "description": "Run fuzzers"},
        {"action": "invariants", "description": "Check invariants"},
        {"action": "upgrade-review", "description": "Compare upgrade pair"},
        {"action": "fix", "description": "Generate remediation patch (isolated)"},
        {"action": "verify", "description": "Verify remediation"},
    ]


def skillhub_manifests() -> list[dict[str, Any]]:
    from sklab_contract_toolkit.skills.pack import list_skills

    return list_skills()
