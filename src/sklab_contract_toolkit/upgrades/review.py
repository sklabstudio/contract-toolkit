"""Upgrade review: proxy pattern, admin, initializer, storage, auth changes."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from sklab_contract_toolkit.core.pathsafety import resolve_root
from sklab_contract_toolkit.detection.solidity import inventory_contracts
from sklab_contract_toolkit.models.results import UpgradeVerdict
from sklab_contract_toolkit.upgrades.storage import diff_storage, extract_storage_layouts


def detect_proxy_pattern(source: str, inheritance: list[str]) -> str:
    if "UUPSUpgradeable" in inheritance or "proxiableUUID" in source:
        return "UUPS"
    if "TransparentUpgradeableProxy" in source or "changeAdmin" in source:
        return "Transparent"
    if "BeaconProxy" in source or "IBeacon" in source:
        return "Beacon"
    if "ERC1967Proxy" in source or "eip1967" in source.lower():
        return "EIP-1967"
    if "Diamond" in source or "diamondCut" in source:
        return "Diamond"
    if "delegatecall" in source and ("implementation" in source or "upgrade" in source.lower()):
        return "Custom-Proxy"
    return "None"


def summarize_upgradeability(root: Path | str) -> dict[str, Any]:
    root_path = resolve_root(root)
    out: dict[str, Any] = {}
    for model in inventory_contracts(root_path):
        try:
            source = (root_path / model.source_file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            source = ""
        out[model.contract_name] = {
            "proxy_pattern": detect_proxy_pattern(source, model.inheritance),
            "has_initializer": any(f.name.lower().startswith("initializ") for f in model.functions),
            "has_authorize_upgrade": "_authorizeUpgrade" in source,
            "source": model.source_file,
        }
    return out


def review_upgrade(old_root: Path | str, new_root: Path | str) -> UpgradeVerdict:
    old_path = resolve_root(old_root)
    new_path = resolve_root(new_root)
    old_layouts = extract_storage_layouts(old_path)
    new_layouts = extract_storage_layouts(new_path)
    evidence: list[str] = []
    added_all: list[str] = []
    removed_all: list[str] = []
    type_changes_all: list[str] = []
    incompatible = False
    risky = False

    old_models = {m.contract_name: m for m in inventory_contracts(old_path)}
    new_models = {m.contract_name: m for m in inventory_contracts(new_path)}
    proxy_pattern = ""
    for _name, new_model in new_models.items():
        try:
            source = (new_path / new_model.source_file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            source = ""
        pattern = detect_proxy_pattern(source, new_model.inheritance)
        if pattern != "None" and not proxy_pattern:
            proxy_pattern = pattern
    if proxy_pattern:
        evidence.append(f"proxy pattern: {proxy_pattern}")

    for name in sorted(set(old_layouts) | set(new_layouts)):
        old_layout = old_layouts.get(name)
        new_layout = new_layouts.get(name)
        if old_layout is None:
            evidence.append(f"new contract {name}: no layout comparison possible")
            continue
        if new_layout is None:
            evidence.append(f"contract {name} removed in new version")
            risky = True
            continue
        diff = diff_storage(old_layout, new_layout)
        for a in diff["added"]:
            added_all.append(f"{name}.{a}")
        for r in diff["removed"]:
            removed_all.append(f"{name}.{r}")
        for t in diff["type_changes"]:
            type_changes_all.append(f"{name}.{t}")
        if diff["removed"] or diff["type_changes"] or diff["shifted"] or diff["order_changed"]:
            incompatible = True
            evidence.append(
                f"{name}: incompatible layout change "
                f"(removed={diff['removed']}, type_changes={diff['type_changes']}, "
                f"shifted={diff['shifted']}, order={diff['order_changed']})"
            )
        elif diff["added"]:
            # appended-only additions are generally safe for upgradeable contracts
            evidence.append(f"{name}: appended storage {diff['added']} (safe if appended)")
            risky = False

    # inheritance / auth changes
    auth_changes: list[str] = []
    for name in sorted(set(old_models) & set(new_models)):
        old_auth = {f.name for f in old_models[name].functions if f.modifiers}
        new_auth = {f.name for f in new_models[name].functions if f.modifiers}
        if old_auth != new_auth:
            auth_changes.append(f"{name}: guarded-function set changed")
            evidence.append(f"{name}: authorization surface changed")
            risky = True
        if set(old_models[name].inheritance) != set(new_models[name].inheritance):
            auth_changes.append(
                f"{name}: inheritance changed {old_models[name].inheritance} -> {new_models[name].inheritance}"
            )
            evidence.append(f"{name}: inheritance changed")
            risky = True

    if incompatible:
        verdict: Literal["SAFE", "RISKY", "INCOMPATIBLE", "INCONCLUSIVE"] = "INCOMPATIBLE"
    elif risky or not evidence:
        verdict = "RISKY" if risky else "INCONCLUSIVE"
        if not evidence:
            evidence.append("no comparable storage or proxy signals found")
    else:
        verdict = "SAFE"
    return UpgradeVerdict(
        verdict=verdict,
        proxy_pattern=proxy_pattern,
        evidence=evidence,
        storage_added=added_all,
        storage_removed=removed_all,
        storage_type_changes=type_changes_all,
        authorization_changes=auth_changes,
    )
