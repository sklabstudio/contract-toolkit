"""Threat-model template populated with deterministic facts only."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sklab_contract_toolkit.analysis.authorities import extract_authorities
from sklab_contract_toolkit.core.pathsafety import resolve_root
from sklab_contract_toolkit.detection.solidity import inventory_contracts
from sklab_contract_toolkit.upgrades.review import summarize_upgradeability


def build_threat_model(root: Path | str) -> dict[str, Any]:
    root_path = resolve_root(root)
    models = inventory_contracts(root_path)
    authorities = extract_authorities(root_path)
    upgradeability = summarize_upgradeability(root_path)
    assets: list[str] = []
    privileged: list[str] = []
    external_deps: set[str] = set()
    oracle_refs: list[str] = []
    token_transfers: list[str] = []
    for model in models:
        try:
            source = (root_path / model.source_file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            source = ""
        if re.search(r"payable|msg\.value|transfer\(|safeTransfer|_mint", source):
            assets.append(f"{model.contract_name}: handles value/tokens")
        for fn in model.functions:
            if fn.modifiers:
                privileged.append(f"{model.contract_name}.{fn.name} [{','.join(fn.modifiers)}]")
        external_deps.update(model.imports)
        external_deps.update(model.external_dependencies)
        if re.search(r"AggregatorV3Interface|latestRoundData|priceFeed|IOracle|Chainlink", source):
            oracle_refs.append(f"{model.contract_name}: oracle reference")
        for call in model.external_calls:
            token_transfers.append(f"{model.contract_name}: {call.contract}.{call.function} (line {call.line})")
    return {
        "assets": sorted(set(assets)),
        "authorities": [a.model_dump() for a in authorities],
        "privileged_functions": sorted(set(privileged)),
        "external_dependencies": sorted(external_deps),
        "upgradeability": upgradeability,
        "oracle_references": sorted(set(oracle_refs)),
        "token_transfers": sorted(set(token_transfers))[:100],
        "trust_assumptions": [
            "Admin keys/roles are trusted unless placed behind multisig/timelock.",
            "Upgrade admin can replace logic where proxy patterns are present.",
            "Oracles, if referenced, are trusted third parties.",
            "This template states facts only; risk reasoning is out of scope for the public toolkit.",
        ],
    }


def render_threat_model_markdown(tm: dict[str, Any]) -> str:
    lines = ["# Threat Model (public template)", ""]
    for section in (
        "assets",
        "privileged_functions",
        "external_dependencies",
        "oracle_references",
        "token_transfers",
        "trust_assumptions",
    ):
        lines.append(f"## {section.replace('_', ' ').title()}")
        lines.append("")
        items = tm.get(section, [])
        if not items:
            lines.append("- none detected")
        for item in items:
            lines.append(f"- {item}")
        lines.append("")
    lines.append("## Authorities")
    lines.append("")
    for a in tm.get("authorities", []):
        lines.append(f"- {a.get('authority')} → {a.get('target_contract')}: {a.get('capability')}")
    lines.append("")
    return "\n".join(lines)
