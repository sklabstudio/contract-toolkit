"""Public Contract Skill Pack: manifest registry + validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

DATA_DIR = Path(__file__).parent / "data"

AUDITED_PERMISSIONS = {
    "filesystem_read": True,
    "filesystem_write": False,
    "shell": True,
    "network": False,
    "secrets": False,
}


def _load_manifest(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    data["_file"] = path.name
    return data


def list_skills() -> list[dict[str, Any]]:
    skills: list[dict[str, Any]] = []
    if not DATA_DIR.is_dir():
        return skills
    for path in sorted(DATA_DIR.glob("*.yaml")):
        try:
            skills.append(_load_manifest(path))
        except Exception:
            continue
    return skills


def validate_skill(skill: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("name", "description", "workflow", "permissions"):
        if field not in skill:
            errors.append(f"missing field: {field}")
    perms = skill.get("permissions", {})
    if isinstance(perms, dict):
        if perms.get("secrets"):
            errors.append("skills must not request secrets by default")
        if perms.get("network") and skill.get("name") not in ("contract-address-inspect",):
            errors.append(f"skill {skill.get('name')} requests network; only address inspection may")
    if not skill.get("workflow"):
        errors.append("missing workflow steps")
    return errors


def validate_pack() -> dict[str, Any]:
    skills = list_skills()
    report: dict[str, Any] = {"count": len(skills), "skills": [], "errors": []}
    for skill in skills:
        errs = validate_skill(skill)
        report["skills"].append({"name": skill.get("name"), "ok": not errs, "errors": errs})
        report["errors"].extend([f"{skill.get('name')}: {e}" for e in errs])
    return report
