"""Authority / permission extraction: Ownable, AccessControl, custom roles."""

from __future__ import annotations

import re
from pathlib import Path

from sklab_contract_toolkit.core.pathsafety import resolve_root
from sklab_contract_toolkit.detection.solidity import inventory_contracts
from sklab_contract_toolkit.models.project import AuthorityRecord

_ROLE_CONST_RE = re.compile(r"\bbytes32\s+(?:public\s+)?(?:constant\s+)?(\w*ROLE\w*)\s*=", re.IGNORECASE)
_MULTISIG_RE = re.compile(r"multisig|gnosissafe|safe\.sol|MultiSig", re.IGNORECASE)
_TIMELOCK_RE = re.compile(r"timelock|TimelockController|_schedule|delay", re.IGNORECASE)


def extract_authorities(root: Path | str) -> list[AuthorityRecord]:
    root_path = resolve_root(root)
    records: list[AuthorityRecord] = []
    for model in inventory_contracts(root_path):
        fn_names = {f.name for f in model.functions}
        # owner / admin state variables are authority evidence even without modifiers
        for var in model.state_variables:
            if var.name.lower() in ("owner", "admin", "governor", "pauser", "minter", "operator"):
                records.append(
                    AuthorityRecord(
                        authority=var.name,
                        capability=f"holds {var.name} powers",
                        target_contract=model.contract_name,
                        evidence=f"state variable {var.name} ({var.type}) in {model.source_file}",
                        confidence="MEDIUM",
                    )
                )
        # Ownable
        if "owner" in fn_names or "Ownable" in model.inheritance:
            records.append(
                AuthorityRecord(
                    authority="owner",
                    capability="owns/administers contract",
                    target_contract=model.contract_name,
                    evidence=f"Ownable inheritance={model.inheritance} owner() present={'owner' in fn_names}",
                    confidence="HIGH" if "Ownable" in model.inheritance else "MEDIUM",
                )
            )
        # AccessControl roles
        if "AccessControl" in model.inheritance or {"hasRole", "grantRole"} & fn_names:
            records.append(
                AuthorityRecord(
                    authority="DEFAULT_ADMIN_ROLE",
                    capability="grant/revoke roles",
                    target_contract=model.contract_name,
                    evidence="AccessControl pattern detected",
                    confidence="HIGH",
                )
            )
        # role constants from source
        try:
            source = (root_path / model.source_file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            source = ""
        for m in _ROLE_CONST_RE.finditer(source):
            role = m.group(1)
            if not any(r.authority == role and r.target_contract == model.contract_name for r in records):
                records.append(
                    AuthorityRecord(
                        authority=role,
                        capability="custom role (see source for grants)",
                        target_contract=model.contract_name,
                        evidence=f"role constant {role} in {model.source_file}",
                        confidence="MEDIUM",
                    )
                )
        # custom admin modifiers
        for mod in model.modifiers:
            if re.search(r"only|admin|owner|role|auth", mod.name, re.IGNORECASE):
                records.append(
                    AuthorityRecord(
                        authority=mod.name,
                        capability="custom access-control modifier",
                        target_contract=model.contract_name,
                        evidence=f"modifier {mod.name} in {model.source_file}",
                        confidence="MEDIUM",
                    )
                )
        # privileged functions
        for fn in model.functions:
            if any(m in ("onlyOwner", "onlyRole", "onlyAdmin") for m in fn.modifiers):
                records.append(
                    AuthorityRecord(
                        authority=fn.modifiers[0] if fn.modifiers else "admin",
                        capability=f"can call {fn.name}",
                        target_contract=model.contract_name,
                        evidence=f"{fn.name} guarded by {fn.modifiers} ({model.source_file}:{fn.line})",
                        confidence="HIGH",
                    )
                )
        # pauser / minter / operator / governor keywords
        for keyword, cap in (
            ("pauser", "can pause"),
            ("minter", "can mint"),
            ("operator", "operator powers"),
            ("governor", "governance powers"),
            ("upgrade", "can upgrade implementation"),
        ):
            for fn in model.functions:
                if keyword in fn.name.lower():
                    records.append(
                        AuthorityRecord(
                            authority=fn.name,
                            capability=cap,
                            target_contract=model.contract_name,
                            evidence=f"function {fn.name} ({model.source_file}:{fn.line})",
                            confidence="LOW",
                        )
                    )
                    break
        if _MULTISIG_RE.search(source):
            records.append(
                AuthorityRecord(
                    authority="multisig",
                    capability="multisig-gated administration",
                    target_contract=model.contract_name,
                    evidence="multisig reference in source",
                    confidence="LOW",
                )
            )
        if _TIMELOCK_RE.search(source):
            records.append(
                AuthorityRecord(
                    authority="timelock",
                    capability="delayed administration",
                    target_contract=model.contract_name,
                    evidence="timelock reference in source",
                    confidence="LOW",
                )
            )
    # Never overclaim: drop exact duplicates
    seen: set[tuple[str, str, str]] = set()
    unique: list[AuthorityRecord] = []
    for r in records:
        key = (r.authority, r.target_contract, r.capability)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique
