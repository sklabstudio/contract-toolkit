"""Remediation (fix) + verification (verify) workflows.

Default: return a patch in an isolated workspace; never modify the source
repo directly unless explicitly requested; never push automatically.
"""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

from sklab_contract_toolkit.analysis.engine import run_internal_analysis
from sklab_contract_toolkit.core.pathsafety import resolve_root
from sklab_contract_toolkit.integrations.connectors import patchbench_verify
from sklab_contract_toolkit.models.findings import ContractFinding
from sklab_contract_toolkit.models.results import VerificationResult
from sklab_contract_toolkit.testing.flows import compile_project

_FIX_SNIPPETS: dict[str, str] = {
    "SKLAB-TX-ORIGIN-001": (
        'Replace `tx.origin` with `msg.sender`:\n\n```solidity\nrequire(msg.sender == owner, "not authorized");\n```'
    ),
    "SKLAB-DELEGATECALL-001": (
        "Pin the delegatecall target to an immutable trusted implementation and gate callers:\n\n"
        "```solidity\naddress private immutable _implementation;\n"
        'require(msg.sender == admin, "not admin");\n'
        "(bool ok, ) = _implementation.delegatecall(msg.data);\n"
        'require(ok, "delegatecall failed");\n```'
    ),
    "SKLAB-SELFDESTRUCT-001": (
        "Remove `selfdestruct`, or gate behind timelock + multisig with a documented recovery plan."
    ),
    "SKLAB-UNCHECKED-CALL-001": (
        "Check low-level call results:\n\n```solidity\n"
        '(bool success, ) = target.call{value: amount}("");\n'
        'require(success, "call failed");\n```'
    ),
    "SKLAB-INIT-001": (
        "Add the initializer guard and disable initializers on the implementation:\n\n```solidity\n"
        "function initialize(address owner_) external initializer { ... }\n"
        "constructor() { _disableInitializers(); }\n```"
    ),
    "SKLAB-INIT-002": "Restrict the initializer (owner/factory) or document open-initialization assumptions.",
    "SKLAB-UPGRADE-001": (
        "Gate upgrades:\n\n```solidity\n"
        "function _authorizeUpgrade(address next) internal override onlyRole(UPGRADER_ROLE) {}\n```"
    ),
    "SKLAB-REENTRANCY-001": "Apply checks-effects-interactions and `nonReentrant`; prefer pull payments.",
    "SKLAB-APPROVAL-001": "Use exact allowances or `safeIncreaseAllowance` instead of `type(uint256).max`.",
    "SKLAB-TIMESTAMP-001": "Avoid `block.timestamp` for randomness; use margins for deadlines.",
    "SKLAB-DOS-001": "Bound batch sizes / paginate loops over storage arrays.",
    "SKLAB-STORAGE-001": "Add `uint256[50] private __gap;` (or EIP-7201 namespaced storage).",
    "SKLAB-AUTH-001": "Split roles, add timelock/multisig, document admin powers.",
    "SKLAB-AUTH-002": "Replace hardcoded addresses with immutable constructor params or governed config.",
    "SKLAB-AUTH-003": (
        "Restrict the sensitive function:\n\n```solidity\n"
        "function mint(address to, uint256 value) external onlyOwner {\n"
        '    require(totalSupply + value <= MAX_SUPPLY, "cap exceeded");\n'
        "    ...\n}\n```\nThen add tests proving unauthorized mint reverts."
    ),
}


def _load_finding(ref: str, root: Path) -> ContractFinding | None:
    """Resolve a finding ref: rule-id prefix match against current analysis.

    Searches internal rules first, then Slither findings (when installed), so
    every ID emitted by `analyze` resolves in `fix`/`verify`.
    """
    for finding in run_internal_analysis(root):
        if finding.id == ref or finding.rule_id == ref or ref in finding.id:
            return finding
    try:
        from sklab_contract_toolkit.analysis.slither_norm import run_slither

        slither = run_slither(root)
        for finding in slither.get("findings", []) or []:
            if finding.id == ref or finding.rule_id == ref or ref in finding.id:
                return finding
    except Exception:
        pass
    return None


def prepare_fix(ref: str, root: Path | str, out_dir: Path | str | None = None, isolated: bool = True) -> dict[str, Any]:
    root_path = resolve_root(root)
    finding = _load_finding(ref, root_path)
    if finding is None:
        return {
            "ok": False,
            "error": f"finding not found: {ref}",
            "notes": "Run `sklab-contract analyze` to list finding IDs.",
        }
    snippet = _FIX_SNIPPETS.get(finding.rule_id, "Review the finding evidence and apply the recommendation.")
    file_path = root_path / finding.file if finding.file else None
    original = ""
    if file_path and file_path.is_file():
        try:
            original = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            original = ""
    patch_body = (
        f"# Remediation for {finding.id} ({finding.rule_id} {finding.rule_version})\n"
        f"# Location: {finding.file}:{finding.line} contract={finding.contract} function={finding.function}\n"
        f"# Manual step: apply the snippet below in an isolated workspace, then verify.\n\n{snippet}\n"
    )
    if out_dir is not None:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{finding.id}.patch.md").write_text(patch_body, encoding="utf-8")
        if original:
            patched = original + f"\n// SKLAB-FIX({finding.rule_id}): see {finding.id}.patch.md\n"
            diff = "".join(
                difflib.unified_diff(
                    original.splitlines(True),
                    patched.splitlines(True),
                    fromfile=f"a/{finding.file}",
                    tofile=f"b/{finding.file}",
                )
            )
            (out / f"{finding.id}.diff").write_text(diff, encoding="utf-8")
    assessment = patchbench_verify(patch_body, {"finding": finding.id})
    return {
        "ok": True,
        "finding": finding.model_dump(),
        "patch": patch_body,
        "isolated": isolated,
        "modified_source_repo": False,
        "patchbench": assessment,
    }


def verify_fix(ref: str, root: Path | str) -> VerificationResult:
    root_path = resolve_root(root)
    # Re-run compile + analysis; the finding should be gone if fixed.
    compile_result = compile_project(root_path)
    current_ids = set()
    current_rules: dict[str, int] = {}
    for finding in run_internal_analysis(root_path):
        current_ids.add(finding.id)
        current_rules[finding.rule_id] = current_rules.get(finding.rule_id, 0) + 1
    checks = {
        "compile_success": "PASS" if compile_result.get("success") else "FAIL",
        "finding_absent": "UNKNOWN"
        if ref in ("", "report")
        else (
            "PASS"
            if not any(ref in fid or fid.startswith(ref) for fid in current_ids) and ref not in current_rules
            else "FAIL"
        ),
    }
    if checks["finding_absent"] == "PASS" and checks["compile_success"] == "PASS":
        return VerificationResult(
            status="FIXED_VERIFIED",  # type: ignore[arg-type]
            evidence=[f"finding {ref} absent after re-analysis", "compile succeeded"],
            checks=checks,
        )
    if checks["finding_absent"] == "PASS":
        return VerificationResult(
            status="FIXED_UNVERIFIED",  # type: ignore[arg-type]
            evidence=[f"finding {ref} absent but compile did not pass"],
            checks=checks,
        )
    if ref in current_rules or any(ref in fid for fid in current_ids):
        return VerificationResult(
            status="NOT_FIXED",  # type: ignore[arg-type]
            evidence=[f"finding {ref} still present"],
            checks=checks,
        )
    return VerificationResult(
        status="INCONCLUSIVE",  # type: ignore[arg-type]
        evidence=["could not resolve finding reference"],
        checks=checks,
    )
