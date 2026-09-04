"""Versioned internal deterministic static rules (public, conservative).

Each rule has a stable rule_id + rule_version. Changing rule semantics
requires bumping rule_version. Rules are heuristic by default and must not
claim exploitability without evidence.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sklab_contract_toolkit.models.contract import ContractModel
from sklab_contract_toolkit.models.findings import Confidence, ContractFinding, Severity

RULESET_VERSION = "1.0.0"


@dataclass
class Rule:
    rule_id: str
    rule_version: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    description: str
    recommendation: str
    cwe: str = ""
    swc: str = ""
    check: Callable[[ContractModel, str, str], list[ContractFinding]] | None = field(default=None, repr=False)


def _mk(rule: Rule, model: ContractModel, rel: str, function: str, line: int, evidence: str) -> ContractFinding:
    return ContractFinding(
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        title=rule.title,
        category=rule.category,
        severity=rule.severity,
        confidence=rule.confidence,  # type: ignore[arg-type]
        evidence_level="HEURISTIC",
        contract=model.contract_name,
        function=function,
        file=rel,
        line=line,
        description=rule.description,
        evidence=evidence,
        cwe=rule.cwe,
        swc=rule.swc,
        tool="sklab-internal",
        tool_rule=rule.rule_id,
        recommendation=rule.recommendation,
    ).with_fingerprint()


def _source_of(root: Path, rel: str) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _rule_tx_origin(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-TX-ORIGIN-001"]
    out: list[ContractFinding] = []
    for m in re.finditer(r"tx\.origin", source):
        line = source.count("\n", 0, m.start()) + 1
        # find enclosing function name heuristically
        fn_name = ""
        for fn in model.functions:
            if fn.line <= line:
                fn_name = fn.name
        out.append(
            _mk(
                rule,
                model,
                rel,
                fn_name,
                line,
                f"tx.origin used at line {line}: {source.splitlines()[line - 1].strip()[:160]}",
            )
        )
    return out


def _rule_delegatecall(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-DELEGATECALL-001"]
    out: list[ContractFinding] = []
    for m in re.finditer(r"\.delegatecall\s*[\(\{]", source):
        line = source.count("\n", 0, m.start()) + 1
        context = "\n".join(source.splitlines()[max(0, line - 3) : line + 2])
        fn_name = ""
        for fn in model.functions:
            if fn.line <= line:
                fn_name = fn.name
        # flag as suspicious when target looks user-controllable or in a public function
        out.append(
            _mk(
                rule,
                model,
                rel,
                fn_name,
                line,
                f"delegatecall indicator at line {line} (verify target is trusted/immutable):\n{context[:500]}",
            )
        )
    return out


def _rule_selfdestruct(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-SELFDESTRUCT-001"]
    out: list[ContractFinding] = []
    for m in re.finditer(r"\bselfdestruct\s*\(|\bsuicide\s*\(", source):
        line = source.count("\n", 0, m.start()) + 1
        fn_name = ""
        for fn in model.functions:
            if fn.line <= line:
                fn_name = fn.name
        out.append(_mk(rule, model, rel, fn_name, line, f"selfdestruct usage at line {line}"))
    return out


def _rule_unchecked_call(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-UNCHECKED-CALL-001"]
    out: list[ContractFinding] = []
    for m in re.finditer(
        r"\(\s*bool\s+\w*\s*,?\s*(bytes\s+memory\s+\w+)?\s*\)\s*=\s*\w+[\w\.\(\)\[\]\s,]*\.(call|send)\s*[\(\{]", source
    ):
        line = source.count("\n", 0, m.start()) + 1
        after = source[m.end() : m.end() + 400]
        if not re.search(r"require\s*\(|if\s*\(|assert\s*\(|revert", after):
            fn_name = ""
            for fn in model.functions:
                if fn.line <= line:
                    fn_name = fn.name
            out.append(_mk(rule, model, rel, fn_name, line, f"low-level call result may be unchecked near line {line}"))
    # simpler pattern: `.call{...}(...)` without surrounding require within 3 lines
    for m in re.finditer(r"\.call\s*\{[^;]*\}\s*\([^;]*\)\s*;", source):
        snippet = m.group(0)
        line = source.count("\n", 0, m.start()) + 1
        start_line = max(0, line - 3)
        window = "\n".join(source.splitlines()[start_line : line + 2])
        if not re.search(r"require|revert|assert|if\s*\(", window):
            fn_name = ""
            for fn in model.functions:
                if fn.line <= line:
                    fn_name = fn.name
            if not any(f.function == fn_name and f.line == line for f in out):
                out.append(
                    _mk(rule, model, rel, fn_name, line, f"unchecked low-level call near line {line}: {snippet[:160]}")
                )
    return out


def _rule_missing_initializer(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-INIT-001"]
    out: list[ContractFinding] = []
    is_upgradeable = bool(re.search(r"Initializable|UUPSUpgradeable|_disableInitializers|initializer", source))
    has_initialize = any(f.name.lower().startswith("initializ") for f in model.functions)
    if is_upgradeable or has_initialize:
        for fn in model.functions:
            if (
                fn.name.lower().startswith("initializ")
                and "initializer" not in " ".join(fn.modifiers).lower()
                and "reinitializer" not in " ".join(fn.modifiers).lower()
            ):
                # check raw source for modifier presence
                if not re.search(rf"function\s+{re.escape(fn.name)}\b[^{{;]*\binitializer\b", source):
                    out.append(
                        _mk(
                            rule,
                            model,
                            rel,
                            fn.name,
                            fn.line,
                            f"initializer-like function '{fn.name}' lacks an initializer guard modifier",
                        )
                    )
        if (
            has_initialize
            and "_disableInitializers" not in source
            and "constructor" not in {f.name for f in model.functions}
        ):
            out.append(
                _mk(
                    rule,
                    model,
                    rel,
                    "",
                    1,
                    "upgradeable contract has initialize() but no _disableInitializers in constructor",
                )
            )
    return out


def _rule_broad_owner(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-AUTH-001"]
    out: list[ContractFinding] = []
    owner_guarded = [
        f for f in model.functions if any(m in ("onlyOwner", "onlyRole", "onlyAdmin") for m in f.modifiers)
    ]
    if len(owner_guarded) >= 4:
        worst = owner_guarded[0]
        out.append(
            _mk(
                rule,
                model,
                rel,
                worst.name,
                worst.line,
                f"{len(owner_guarded)} privileged functions guarded by owner/admin role "
                f"({', '.join(f.name for f in owner_guarded[:8])}); review least-privilege",
            )
        )
    return out


def _rule_hardcoded_admin(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-AUTH-002"]
    out: list[ContractFinding] = []
    for m in re.finditer(r"\b0x[0-9a-fA-F]{40}\b", source):
        line = source.count("\n", 0, m.start()) + 1
        window = "\n".join(source.splitlines()[max(0, line - 2) : line + 1])
        if re.search(r"owner|admin|treasury|fee|recipient| multisig", window, re.IGNORECASE):
            out.append(
                _mk(
                    rule,
                    model,
                    rel,
                    "",
                    line,
                    f"hardcoded address {m.group(0)} near privileged identifier (line {line})",
                )
            )
            if len(out) >= 5:
                break
    return out


def _rule_reentrancy_pattern(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-REENTRANCY-001"]
    out: list[ContractFinding] = []
    for fn in model.functions:
        # locate function body crudely: from fn.line, next 60 lines
        lines = source.splitlines()
        start = max(0, fn.line - 1)
        window_lines = lines[start : start + 80]
        call_idx = [
            i for i, ln in enumerate(window_lines) if re.search(r"\.call\s*[\{\(]|\.transfer\s*\(|\.send\s*\(", ln)
        ]
        state_idx = [
            i
            for i, ln in enumerate(window_lines)
            if re.search(r"\w+\s*(\[.*\])?\s*(=|\+=|-=)\s*[^=]", ln) and "==" not in ln
        ]
        if call_idx and state_idx and min(call_idx) < max(state_idx):
            if "nonReentrant" not in fn.modifiers:
                out.append(
                    _mk(
                        rule,
                        model,
                        rel,
                        fn.name,
                        fn.line,
                        f"external call before state change pattern in '{fn.name}' without nonReentrant "
                        f"(heuristic; verify checks-effects-interactions)",
                    )
                )
    return out


def _rule_unbounded_loop(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-DOS-001"]
    out: list[ContractFinding] = []
    for m in re.finditer(r"\bfor\s*\([^;]*;[^;]*;[^)]*\)", source):
        line = source.count("\n", 0, m.start()) + 1
        window = "\n".join(source.splitlines()[line - 1 : line + 12])
        if re.search(r"\.length|storage|push|pop", window):
            fn_name = ""
            for fn in model.functions:
                if fn.line <= line:
                    fn_name = fn.name
            out.append(
                _mk(
                    rule,
                    model,
                    rel,
                    fn_name,
                    line,
                    f"unbounded loop over storage-length array near line {line} (DoS/gas risk)",
                )
            )
    return out


def _rule_timestamp(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-TIMESTAMP-001"]
    out: list[ContractFinding] = []
    for m in re.finditer(r"\bblock\.timestamp\b|\bnow\b", source):
        line = source.count("\n", 0, m.start()) + 1
        fn_name = ""
        for fn in model.functions:
            if fn.line <= line:
                fn_name = fn.name
        out.append(
            _mk(
                rule,
                model,
                rel,
                fn_name,
                line,
                f"timestamp dependence at line {line} (miner-manipulable within bounds; "
                f"avoid for randomness/critical deadlines)",
            )
        )
        if len(out) >= 5:
            break
    return out


def _rule_unsafe_approval(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-APPROVAL-001"]
    out: list[ContractFinding] = []
    for m in re.finditer(r"\.approve\s*\([^)]*type\s*\(\s*uint256\s*\)\s*\.max", source):
        line = source.count("\n", 0, m.start()) + 1
        fn_name = ""
        for fn in model.functions:
            if fn.line <= line:
                fn_name = fn.name
        out.append(
            _mk(
                rule,
                model,
                rel,
                fn_name,
                line,
                f"unbounded approval (type(uint256).max) at line {line}; prefer exact allowances",
            )
        )
    # approve inside a loop or without zero-first pattern note
    for m in re.finditer(r"\.approve\s*\(", source):
        line = source.count("\n", 0, m.start()) + 1
        window = "\n".join(source.splitlines()[max(0, line - 2) : line + 3])
        if "safeApprove" not in window and "safeIncreaseAllowance" not in window:
            fn_name = ""
            for fn in model.functions:
                if fn.line <= line:
                    fn_name = fn.name
            # only one generic info per function
            if not any(f.function == fn_name and f.rule_id == rule.rule_id for f in out):
                out.append(
                    _mk(
                        rule,
                        model,
                        rel,
                        fn_name,
                        line,
                        f"ERC-20 approve at line {line}; verify allowance race handling "
                        f"(consider safeIncreaseAllowance)",
                    )
                )
    return out


def _rule_storage_gap(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-STORAGE-001"]
    out: list[ContractFinding] = []
    is_upgradeable = bool(
        re.search(r"Initializable|UUPSUpgradeable|TransparentUpgradeableProxy|upgradeable", source, re.IGNORECASE)
    )
    if is_upgradeable and "__gap" not in source:
        out.append(
            _mk(
                rule,
                model,
                rel,
                "",
                1,
                "upgradeable contract without storage gap (__gap); future upgrades may shift layout",
            )
        )
    return out


def _rule_public_initializer(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-INIT-002"]
    out: list[ContractFinding] = []
    for fn in model.functions:
        if fn.name.lower().startswith("initializ") and fn.visibility in ("public", "external"):
            out.append(
                _mk(
                    rule,
                    model,
                    rel,
                    fn.name,
                    fn.line,
                    f"initializer '{fn.name}' is {fn.visibility}; ensure it is callable exactly once",
                )
            )
    return out


def _rule_upgrade_auth(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-UPGRADE-001"]
    out: list[ContractFinding] = []
    for m in re.finditer(r"function\s+_authorizeUpgrade\b[^{]*\{", source):
        line = source.count("\n", 0, m.start()) + 1
        body = source[m.end() : m.end() + 600]
        if not re.search(r"onlyOwner|onlyRole|onlyAdmin|_checkOwner|_checkRole", body):
            out.append(
                _mk(
                    rule,
                    model,
                    rel,
                    "_authorizeUpgrade",
                    line,
                    "_authorizeUpgrade without visible access-control check (critical if reachable)",
                )
            )
    return out


_SENSITIVE_UNGUARDED = frozenset(
    {
        "mint",
        "safemint",
        "burn",
        "burnfrom",
        "pause",
        "unpause",
        "upgradeto",
        "setupgrade",
        "setadmin",
        "setowner",
        "transferownership",
        "grantrole",
        "revokerole",
        "mintto",
        "mintbatch",
    }
)


def _iter_function_bodies(source: str):
    """Yield (name, clause, body, line) with exact brace-matched bodies."""
    for m in re.finditer(r"function\s+(\w+)\s*\([^;{}]*?\)\s*([^{};]*)\{", source):
        name, clause = m.group(1), m.group(2)
        depth = 1
        i, n = m.end(), len(source)
        in_str: str | None = None
        while i < n and depth > 0:
            ch = source[i]
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
            elif ch in ("'", '"'):
                in_str = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        yield name, clause, source[m.end() : i - 1], source.count("\n", 0, m.start()) + 1


def _rule_unprotected_sensitive(model: ContractModel, rel: str, source: str) -> list[ContractFinding]:
    rule = RULES["SKLAB-AUTH-003"]
    out: list[ContractFinding] = []
    for name, clause, body, line in _iter_function_bodies(source):
        if name.lower() not in _SENSITIVE_UNGUARDED:
            continue
        if re.search(r"\b(private|internal)\b", clause):
            continue
        if re.search(
            r"\b(onlyOwner|onlyRole|onlyAdmin|onlyPauser|onlyMinter|nonReentrant|"
            r"whenNotPaused|whenPaused|initializer|reinitializer|auth|authorized)\b",
            clause,
        ):
            continue
        if re.search(
            r"msg\.sender|_msgSender|tx\.origin|\bowner\b|\brole\b|\badmin\b|"
            r"\brequire\s*\(|\brevert\b|\bif\s*\(",
            body,
        ):
            continue
        out.append(
            _mk(
                rule,
                model,
                rel,
                name,
                line,
                f"sensitive function '{name}' is externally reachable with no access-control "
                f"modifier and no visible caller guard in its body (heuristic; confirm "
                f"intended authorization)",
            )
        )
    return out


RULES: dict[str, Rule] = {}


def _register(rule: Rule) -> Rule:
    RULES[rule.rule_id] = rule
    return rule


_register(
    Rule(
        "SKLAB-TX-ORIGIN-001",
        "1.0.0",
        "tx.origin used for authorization",
        "TX_ORIGIN",
        "HIGH",
        "HIGH",
        "tx.origin is spoofable via intermediary contracts; use msg.sender.",
        "Replace tx.origin checks with msg.sender (plus explicit allowlists/roles).",
        cwe="CWE-477",
        swc="SWC-115",
        check=_rule_tx_origin,
    )
)
_register(
    Rule(
        "SKLAB-DELEGATECALL-001",
        "1.0.0",
        "delegatecall to untrusted target indicator",
        "UNSAFE_DELEGATECALL",
        "HIGH",
        "MEDIUM",
        "delegatecall executes foreign code in this contract's storage context.",
        "Hardcode/trust-list delegatecall targets; restrict callers; review storage collisions.",
        cwe="CWE-829",
        swc="SWC-112",
        check=_rule_delegatecall,
    )
)
_register(
    Rule(
        "SKLAB-SELFDESTRUCT-001",
        "1.0.0",
        "selfdestruct usage",
        "SELFDESTRUCT",
        "HIGH",
        "HIGH",
        "selfdestruct irreversibly removes contract code and redirects funds.",
        "Remove selfdestruct or gate behind timelock/multisig with documented recovery plan.",
        cwe="CWE-404",
        swc="SWC-106",
        check=_rule_selfdestruct,
    )
)
_register(
    Rule(
        "SKLAB-UNCHECKED-CALL-001",
        "1.0.0",
        "unchecked low-level call result",
        "UNCHECKED_RETURN",
        "MEDIUM",
        "MEDIUM",
        "Low-level call/send return values must be checked.",
        "Wrap calls in require(success) or check return booleans explicitly.",
        cwe="CWE-252",
        swc="SWC-104",
        check=_rule_unchecked_call,
    )
)
_register(
    Rule(
        "SKLAB-INIT-001",
        "1.0.0",
        "missing initializer guard indicator",
        "INITIALIZATION",
        "HIGH",
        "MEDIUM",
        "Upgradeable contracts must guard initialize() and disable initializers on implementation.",
        "Add initializer modifier and call _disableInitializers() in constructor.",
        cwe="CWE-665",
        swc="SWC-118",
        check=_rule_missing_initializer,
    )
)
_register(
    Rule(
        "SKLAB-INIT-002",
        "1.0.0",
        "public/external initializer callable",
        "INITIALIZATION",
        "MEDIUM",
        "MEDIUM",
        "Initializers callable by anyone risk front-running unless guarded.",
        "Restrict initializer (owner/factory) or document open-initialization assumptions.",
        cwe="CWE-665",
        swc="SWC-118",
        check=_rule_public_initializer,
    )
)
_register(
    Rule(
        "SKLAB-AUTH-001",
        "1.0.0",
        "broad owner/admin powers",
        "AUTHORITY",
        "MEDIUM",
        "MEDIUM",
        "Many privileged functions concentrate trust in one key/role.",
        "Apply least privilege: split roles, add timelock/multisig, document admin powers.",
        cwe="CWE-250",
        check=_rule_broad_owner,
    )
)
_register(
    Rule(
        "SKLAB-AUTH-002",
        "1.0.0",
        "hardcoded privileged address",
        "CONFIGURATION",
        "LOW",
        "MEDIUM",
        "Hardcoded addresses reduce flexibility and hide trust assumptions.",
        "Make privileged addresses immutable constructor params or governed config.",
        cwe="CWE-798",
        check=_rule_hardcoded_admin,
    )
)
_register(
    Rule(
        "SKLAB-AUTH-003",
        "1.0.0",
        "sensitive function without visible access control",
        "ACCESS_CONTROL",
        "MEDIUM",
        "LOW",
        "Mint/burn/pause/upgrade/role-granting functions reachable by anyone "
        "risk unauthorized supply or privilege changes; heuristic only.",
        "Add onlyOwner/onlyRole (or explicit caller checks), emit events, and cover with tests.",
        cwe="CWE-284",
        check=_rule_unprotected_sensitive,
    )
)
_register(
    Rule(
        "SKLAB-REENTRANCY-001",
        "1.0.0",
        "external call before state change pattern",
        "REENTRANCY",
        "MEDIUM",
        "LOW",
        "Heuristic pattern only; verify checks-effects-interactions manually.",
        "Follow checks-effects-interactions; add nonReentrant where appropriate; use pull payments.",
        cwe="CWE-841",
        swc="SWC-107",
        check=_rule_reentrancy_pattern,
    )
)
_register(
    Rule(
        "SKLAB-DOS-001",
        "1.0.0",
        "unbounded loop over storage array",
        "DENIAL_OF_SERVICE",
        "MEDIUM",
        "MEDIUM",
        "Loops bounded only by storage length can exceed block gas limits.",
        "Paginate, bound batch sizes, or use pull patterns.",
        cwe="CWE-400",
        swc="SWC-128",
        check=_rule_unbounded_loop,
    )
)
_register(
    Rule(
        "SKLAB-TIMESTAMP-001",
        "1.0.0",
        "timestamp dependence indicator",
        "ORACLE",
        "LOW",
        "MEDIUM",
        "block.timestamp is miner-influenced within small bounds.",
        "Avoid timestamps for randomness; use margins for deadlines; document assumptions.",
        cwe="CWE-829",
        swc="SWC-116",
        check=_rule_timestamp,
    )
)
_register(
    Rule(
        "SKLAB-APPROVAL-001",
        "1.0.0",
        "unsafe/unbounded approval pattern",
        "APPROVAL",
        "LOW",
        "MEDIUM",
        "Unbounded or racy approvals expand token theft blast radius.",
        "Use exact allowances or safeIncreaseAllowance; document approval flows.",
        cwe="CWE-250",
        swc="SWC-114",
        check=_rule_unsafe_approval,
    )
)
_register(
    Rule(
        "SKLAB-STORAGE-001",
        "1.0.0",
        "missing storage gap in upgradeable contract",
        "STORAGE",
        "LOW",
        "MEDIUM",
        "Without __gap, inherited upgrades may collide on storage layout.",
        "Add uint256[50] private __gap (or namespaced storage per EIP-7201).",
        cwe="CWE-665",
        check=_rule_storage_gap,
    )
)
_register(
    Rule(
        "SKLAB-UPGRADE-001",
        "1.0.0",
        "suspicious upgrade authorization",
        "UPGRADEABILITY",
        "HIGH",
        "MEDIUM",
        "_authorizeUpgrade without access control lets anyone upgrade.",
        "Gate _authorizeUpgrade with onlyOwner/onlyRole and timelock.",
        cwe="CWE-284",
        check=_rule_upgrade_auth,
    )
)
