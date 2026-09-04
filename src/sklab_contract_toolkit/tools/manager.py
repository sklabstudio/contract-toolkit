"""Toolchain manager: detect tools, versions, compatibility, fingerprints."""

from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import Any

from sklab_contract_toolkit.core.fingerprints import fingerprint_mapping
from sklab_contract_toolkit.detection.project import detect_project
from sklab_contract_toolkit.tools.adapters import ALL_ADAPTERS
from sklab_contract_toolkit.tools.base import ToolInfo


def list_tools() -> list[ToolInfo]:
    return [adapter.detect() for adapter in ALL_ADAPTERS]


def tools_json() -> list[dict[str, Any]]:
    return [
        {
            "tool": t.tool,
            "installed": t.installed,
            "version": t.version,
            "status": t.status,
            "capabilities": t.capabilities,
            "path": t.path,
            "notes": t.notes,
        }
        for t in list_tools()
    ]


def environment_metadata(offline: bool = False, local_only: bool = False) -> dict[str, Any]:
    tools = {t.tool: t.version for t in list_tools() if t.installed}
    meta = {
        "os": platform.system(),
        "python_version": sys.version.split()[0],
        "tools": tools,
        "offline": offline,
        "local_only": local_only,
    }
    meta["fingerprint"] = fingerprint_mapping({"os": meta["os"], "tools": tools})
    return meta


def choose_toolchain(root: Path | str, preferred: str = "auto") -> dict[str, Any]:
    """Choose preferred toolchain given detection + installed tools."""
    root_path = Path(root).resolve()
    detection = detect_project(root_path)
    installed = {t.tool: t for t in list_tools()}
    forge_ready = installed.get("forge", ToolInfo(tool="forge")).installed
    hardhat_ready = installed.get("hardhat", ToolInfo(tool="hardhat")).installed
    solc_ready = installed.get("solc", ToolInfo(tool="solc")).installed

    if preferred not in ("auto", "foundry", "hardhat", "solc"):
        preferred = "auto"
    chosen = "none"
    reason = ""
    if preferred == "foundry" and forge_ready:
        chosen, reason = "foundry", "explicit preference + forge installed"
    elif preferred == "hardhat" and hardhat_ready:
        chosen, reason = "hardhat", "explicit preference + hardhat installed"
    elif preferred == "solc" and solc_ready:
        chosen, reason = "solc", "explicit preference + solc installed"
    elif detection.kind == "foundry" and forge_ready:
        chosen, reason = "foundry", "Foundry project + forge installed"
    elif detection.kind == "hardhat" and hardhat_ready:
        chosen, reason = "hardhat", "Hardhat project + hardhat installed"
    elif forge_ready and (detection.kind in ("foundry", "mixed_solidity", "raw_solidity", "unknown")):
        chosen, reason = "foundry", "forge available as default EVM toolchain"
    elif hardhat_ready:
        chosen, reason = "hardhat", "hardhat available"
    elif solc_ready:
        chosen, reason = "solc", "solc available"
    else:
        reason = "no EVM toolchain installed; install foundry or hardhat or solc"
    return {
        "project_kind": detection.kind,
        "preferred": preferred,
        "chosen": chosen,
        "reason": reason,
        "forge_installed": forge_ready,
        "hardhat_installed": hardhat_ready,
        "solc_installed": solc_ready,
        "compatible": chosen != "none",
    }
