"""Public standards registry: detect well-known EVM standards by
interface selectors, inheritance, source patterns, and ABI metadata.

Every match returns a confidence in [0, 1]; never claim certainty from
a single weak signal.
"""

from __future__ import annotations

import re
from typing import Any

from sklab_contract_toolkit.detection.solidity import function_selector
from sklab_contract_toolkit.models.contract import ContractModel
from sklab_contract_toolkit.models.project import StandardMatch

# Required function signatures per standard (subset sufficient for detection)
_STANDARD_SIGNATURES: dict[str, list[str]] = {
    "ERC-20": [
        "totalSupply()",
        "balanceOf(address)",
        "transfer(address,uint256)",
        "allowance(address,address)",
        "approve(address,uint256)",
        "transferFrom(address,address,uint256)",
    ],
    "ERC-721": [
        "balanceOf(address)",
        "ownerOf(uint256)",
        "safeTransferFrom(address,address,uint256)",
        "transferFrom(address,address,uint256)",
        "approve(address,uint256)",
        "getApproved(uint256)",
        "setApprovalForAll(address,bool)",
        "isApprovedForAll(address,address)",
        "supportsInterface(bytes4)",
    ],
    "ERC-1155": [
        "balanceOf(address,uint256)",
        "balanceOfBatch(address[],uint256[])",
        "setApprovalForAll(address,bool)",
        "isApprovedForAll(address,address)",
        "safeTransferFrom(address,address,uint256,uint256,bytes)",
        "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
        "supportsInterface(bytes4)",
    ],
    "ERC-165": ["supportsInterface(bytes4)"],
    "ERC-2612": [
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "nonces(address)",
        "DOMAIN_SEPARATOR()",
    ],
    "ERC-4626": [
        "asset()",
        "totalAssets()",
        "convertToShares(uint256)",
        "convertToAssets(uint256)",
        "maxDeposit(address)",
        "previewDeposit(uint256)",
        "deposit(uint256,address)",
        "maxWithdraw(address)",
        "previewWithdraw(uint256)",
        "withdraw(uint256,address,address)",
    ],
    "ERC-2771": ["isTrustedForwarder(address)", "versionRecipient()"],
    "ERC-2981": ["royaltyInfo(uint256,uint256)", "supportsInterface(bytes4)"],
    "ERC-4337": [
        "validateUserOp((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes),bytes32,uint256)",
        "entryPoint()",
    ],
    "EIP-1967": [],
    "UUPS": ["upgradeTo(address)", "upgradeToAndCall(address,bytes)", "proxiableUUID()"],
    "TransparentProxy": ["admin()", "implementation()", "upgradeTo(address)", "changeAdmin(address)"],
    "BeaconProxy": ["implementation()", "beacon()"],
    "Ownable": ["owner()", "transferOwnership(address)", "renounceOwnership()"],
    "AccessControl": [
        "hasRole(bytes32,address)",
        "getRoleAdmin(bytes32)",
        "grantRole(bytes32,address)",
        "revokeRole(bytes32,address)",
    ],
    "Pausable": ["paused()", "pause()", "unpause()"],
}

# Inheritance / import hints mapped to standards
_INHERITANCE_HINTS: dict[str, str] = {
    "ERC20": "ERC-20",
    "ERC721": "ERC-721",
    "ERC1155": "ERC-1155",
    "ERC165": "ERC-165",
    "ERC4626": "ERC-4626",
    "ERC2981": "ERC-2981",
    "UUPSUpgradeable": "UUPS",
    "TransparentUpgradeableProxy": "TransparentProxy",
    "BeaconProxy": "BeaconProxy",
    "Ownable": "Ownable",
    "AccessControl": "AccessControl",
    "Pausable": "Pausable",
}

# Source text patterns mapped to standards
_SOURCE_PATTERNS: dict[str, list[str]] = {
    "EIP-1967": [
        r"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        r"eip1967|EIP1967|_IMPLEMENTATION_SLOT|_ADMIN_SLOT",
    ],
    "UUPS": [r"UUPSUpgradeable|proxiableUUID|_authorizeUpgrade"],
    "TransparentProxy": [r"TransparentUpgradeableProxy|_admin\(\)|changeAdmin"],
    "BeaconProxy": [r"BeaconProxy|IBeacon|upgradeBeacon"],
    "ERC-4337": [r"EntryPoint|validateUserOp|IEntryPoint|UserOperation"],
    "ERC-2771": [r"isTrustedForwarder|ERC2771|_msgSender\(\)"],
    "ERC-2981": [r"royaltyInfo|_setDefaultRoyalty|feeNumerator"],
    "ERC-4626": [r"convertToShares|convertToAssets|previewDeposit|previewWithdraw|totalAssets"],
    "ERC-2612": [r"\bpermit\b|DOMAIN_SEPARATOR|nonces\[|_useNonce"],
    "ERC-20": [r"\btotalSupply\b.*\bbalanceOf\b|\btransferFrom\b.*\ballowance\b"],
    "ERC-721": [r"\bownerOf\b.*\bsafeTransferFrom\b|\btokenURI\b"],
    "ERC-1155": [r"\bbalanceOfBatch\b|\bsafeBatchTransferFrom\b"],
    "Ownable": [r"\bOwnable\b|onlyOwner|_checkOwner|_transferOwnership"],
    "AccessControl": [r"AccessControl|DEFAULT_ADMIN_ROLE|_grantRole|hasRole|onlyRole"],
    "Pausable": [r"\bPausable\b|whenNotPaused|whenPaused|_pause\(\)"],
}


def _contract_signatures(model: ContractModel) -> set[str]:
    sigs: set[str] = set()
    for fn in model.functions:
        if fn.name in ("constructor", "fallback", "receive"):
            continue
        types = []
        for p in fn.params:
            types.append(p.split()[0] if p.split() else "")
        sigs.add(f"{fn.name}({','.join(types)})")
    return sigs


def detect_standards(model: ContractModel, source_text: str = "") -> list[StandardMatch]:
    matches: list[StandardMatch] = []
    sigs = _contract_signatures(model)
    selectors = set()
    for s in sigs:
        try:
            selectors.add(function_selector(s))
        except Exception:
            continue
    for standard, required in _STANDARD_SIGNATURES.items():
        evidence: list[str] = []
        confidence = 0.0
        if required:
            hit = sum(1 for s in required if s in sigs)
            ratio = hit / len(required)
            if hit:
                evidence.append(f"{hit}/{len(required)} interface selectors present")
                confidence += ratio * 0.6
        # inheritance evidence
        for parent in model.inheritance:
            hint = _INHERITANCE_HINTS.get(parent)
            if hint == standard:
                evidence.append(f"inherits {parent}")
                confidence += 0.3
            elif parent == standard or parent.replace("_", "") == standard.replace("-", ""):
                evidence.append(f"inherits {parent}")
                confidence += 0.25
        for imp in model.imports:
            base = imp.split("/")[-1].replace(".sol", "")
            if base in _INHERITANCE_HINTS and _INHERITANCE_HINTS[base] == standard:
                evidence.append(f"imports {imp}")
                confidence += 0.15
        # source patterns
        if source_text:
            for pattern in _SOURCE_PATTERNS.get(standard, []):
                if re.search(pattern, source_text):
                    evidence.append(f"source pattern: {pattern[:48]}")
                    confidence += 0.15
                    break
        # function-name fallback for Ownable/AccessControl/Pausable
        fn_names = {f.name for f in model.functions}
        if standard == "Ownable" and "owner" in fn_names:
            confidence += 0.1
            evidence.append("owner() present")
        if standard == "AccessControl" and fn_names & {"hasRole", "grantRole"}:
            confidence += 0.1
            evidence.append("role functions present")
        if standard == "Pausable" and "paused" in fn_names:
            confidence += 0.1
            evidence.append("paused() present")
        confidence = round(min(confidence, 0.98), 3)
        if evidence and confidence >= 0.15:
            matches.append(StandardMatch(standard=standard, confidence=confidence, evidence=evidence))
    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches


def detect_standards_from_abi(abi_entries: list[dict[str, Any]]) -> list[StandardMatch]:
    names: dict[str, int] = {}
    for entry in abi_entries:
        if entry.get("type") == "function" and entry.get("name"):
            names[entry["name"]] = names.get(entry["name"], 0) + 1
    matches: list[StandardMatch] = []
    for standard, required in _STANDARD_SIGNATURES.items():
        if not required:
            continue
        needed = {s.split("(")[0] for s in required}
        hit = sum(1 for n in needed if n in names)
        ratio = hit / len(needed)
        if ratio >= 0.5:
            matches.append(
                StandardMatch(
                    standard=standard,
                    confidence=round(0.3 + ratio * 0.5, 3),
                    evidence=[f"{hit}/{len(needed)} ABI function names present (source unavailable)"],
                )
            )
    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches


def list_supported_standards() -> list[str]:
    return sorted(_STANDARD_SIGNATURES.keys())
