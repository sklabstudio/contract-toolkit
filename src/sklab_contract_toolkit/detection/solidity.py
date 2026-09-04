"""Deterministic Solidity source parsing: inventory, ABI, selectors.

Regex + brace-tracking heuristics (no compiler required). Conservative:
only report what is safely inferable from source text.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from sklab_contract_toolkit.core.pathsafety import iter_project_files
from sklab_contract_toolkit.models.contract import (
    ContractError,
    ContractEvent,
    ContractFunction,
    ContractModel,
    ContractModifier,
    Dependency,
    ExternalCall,
    StateVariable,
)

# ---------------------------------------------------------------------------
# Minimal pure-Python Keccak-256 (for EVM function selectors, no dependency)
# ---------------------------------------------------------------------------

_KECCAK_ROTC = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_KECCAK_RC = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]
_MASK64 = (1 << 64) - 1


def _rotl(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _MASK64 if n else x & _MASK64


def keccak_256(data: bytes) -> bytes:
    """Keccak-256 (original Keccak padding 0x01, as used by Ethereum)."""
    suffix = b"\x01"
    block_size = 136  # rate for 256-bit output
    suffix_data = data + suffix
    # pad10*1 with 0x80 at end
    pad_len = block_size - (len(suffix_data) % block_size)
    suffix_data += b"\x00" * (pad_len - 1) + b"\x80"
    state = [0] * 25
    for off in range(0, len(suffix_data), block_size):
        block = suffix_data[off : off + block_size]
        for i in range(block_size // 8):
            state[i] ^= int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
        # Keccak-f[1600]
        for rnd in range(24):
            # Theta
            c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
            d = [c[(x + 4) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] = (state[x + 5 * y] ^ d[x]) & _MASK64
            # Rho + Pi
            b = [0] * 25
            for x in range(5):
                for y in range(5):
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(state[x + 5 * y], _KECCAK_ROTC[x][y])
            # Chi
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] = (b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])) & _MASK64
            # Iota
            state[0] = (state[0] ^ _KECCAK_RC[rnd]) & _MASK64
    out = b""
    while len(out) < 32:
        for i in range(min(4, (32 - len(out) + 7) // 8)):
            out += state[i].to_bytes(8, "little")
    return out[:32]


def function_selector(signature: str) -> str:
    """Return 0x + 8 hex chars selector for e.g. 'transfer(address,uint256)'."""
    return "0x" + keccak_256(signature.encode("utf-8")).hex()[:8]


def canonicalize_type(raw: str) -> str:
    t = raw.strip()
    t = re.sub(r"\s+(memory|calldata|storage|payable)\b", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


# ---------------------------------------------------------------------------
# Source parsing
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
_CONTRACT_RE = re.compile(r"(?m)^\s*(?:abstract\s+)?\b(contract|interface|library)\s+(\w+)(?:\s+is\s+([^{;]+))?\s*\{")
_FUNCTION_RE = re.compile(r"\bfunction\s+(\w+|fallback|receive)\s*\(([^)]*)\)\s*([^{;]*)", re.DOTALL)
_EVENT_RE = re.compile(r"\bevent\s+(\w+)\s*\(([^)]*)\)\s*(anonymous)?\s*;", re.DOTALL)
_ERROR_RE = re.compile(r"\berror\s+(\w+)\s*\(([^)]*)\)\s*;", re.DOTALL)
_MODIFIER_RE = re.compile(r"\bmodifier\s+(\w+)\s*(\([^)]*\))?", re.DOTALL)
_IMPORT_RE = re.compile(r"""^\s*import\s+(?:[^'"]*?from\s+)?['"]([^'"]+)['"]""", re.MULTILINE)
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_USING_RE = re.compile(r"\busing\s+(\w+)\s+for\s+([^;]+);")
_LOWLEVEL_RE = re.compile(r"\.\s*(call|delegatecall|staticcall)\s*(\{|\()")
_INTERFACE_CALL_RE = re.compile(r"\b([A-Z]\w*)\s*\(\s*[^)]*\)\s*\.\s*(\w+)\s*\(")
_VIS_RE = re.compile(r"\b(public|external|internal|private)\b")
_MUT_RE = re.compile(r"\b(pure|view|payable)\b")
_KNOWN_MODIFIERS = {
    "onlyOwner",
    "onlyRole",
    "onlyAdmin",
    "whenNotPaused",
    "whenPaused",
    "nonReentrant",
    "initializer",
    "reinitializer",
    "onlyInitializing",
}


def strip_comments(text: str) -> str:
    """Remove // and /* */ comments while respecting string literals."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str: str | None = None
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_str:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_str = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _find_matching_brace(text: str, open_index: int) -> int:
    depth = 0
    in_str: str | None = None
    i = open_index
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_str = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _split_params(raw: str) -> list[str]:
    raw = raw.strip()
    if not raw:
        return []
    parts: list[str] = []
    depth = 0
    current = ""
    for ch in raw:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(canonicalize_type(current))
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(canonicalize_type(current))
    return [p for p in (x.strip() for x in parts) if p]


def _param_types(params: list[str]) -> list[str]:
    types: list[str] = []
    for p in params:
        tokens = p.split()
        if tokens:
            types.append(tokens[0])
    return types


def _parse_body_functions(body: str) -> tuple[list[ContractFunction], list[ExternalCall]]:
    functions: list[ContractFunction] = []
    calls: list[ExternalCall] = []
    for match in _FUNCTION_RE.finditer(body):
        name = match.group(1)
        raw_params = match.group(2) or ""
        clause = match.group(3) or ""
        params = _split_params(raw_params)
        vis = _VIS_RE.search(clause)
        mut = _MUT_RE.search(clause)
        visibility = vis.group(1) if vis else ("external" if name in ("fallback", "receive") else "public")
        mutability = mut.group(1) if mut else "nonpayable"
        clause_noreturns = re.sub(r"\breturns\s*\([^)]*\)", " ", clause)
        modifiers = [
            m
            for m in re.findall(r"\b([A-Za-z_]\w*)\b", clause_noreturns)
            if m
            not in {
                "public",
                "external",
                "internal",
                "private",
                "pure",
                "view",
                "payable",
                "virtual",
                "override",
                "returns",
                "memory",
                "calldata",
                "storage",
            }
        ]
        returns: list[str] = []
        ret_match = re.search(r"\breturns\s*\(([^)]*)\)", clause)
        if ret_match:
            returns = _split_params(ret_match.group(1))
        line = body.count("\n", 0, match.start()) + 1
        selector = ""
        if name not in ("fallback", "receive", "constructor"):
            try:
                sig = f"{name}({','.join(_param_types(params))})"
                selector = function_selector(sig)
            except Exception:
                selector = ""
        functions.append(
            ContractFunction(
                name=name,
                visibility=visibility,
                mutability=mutability,
                params=params,
                returns=returns,
                modifiers=modifiers,
                line=line,
                selector=selector,
            )
        )
    for match in _LOWLEVEL_RE.finditer(body):
        line = body.count("\n", 0, match.start()) + 1
        calls.append(
            ExternalCall(function=match.group(1), line=line, low_level=True, evidence=match.group(0).strip()[:120])
        )
    for match in _INTERFACE_CALL_RE.finditer(body):
        line = body.count("\n", 0, match.start()) + 1
        calls.append(
            ExternalCall(
                contract=match.group(1),
                function=match.group(2),
                line=line,
                low_level=False,
                evidence=match.group(0).strip()[:120],
            )
        )
    return functions, calls


def _parse_state_vars(body: str) -> list[StateVariable]:
    """Collect depth-0 semicolon segments that look like state variable declarations."""
    segments: list[tuple[str, int]] = []
    depth = 0
    current = ""
    seg_line = 1
    line = 1
    in_str: str | None = None
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\n":
            line += 1
        if in_str:
            current += ch
            if ch == "\\":
                if i + 1 < len(body):
                    current += body[i + 1]
                    i += 2
                    continue
            elif ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_str = ch
            current += ch
        elif ch == "{":
            depth += 1
            current = ""
            seg_line = line
        elif ch == "}":
            depth = max(0, depth - 1)
            current = ""
            seg_line = line
        elif ch == ";" and depth == 0:
            segments.append((current.strip(), seg_line))
            current = ""
            seg_line = line
        else:
            current += ch
        i += 1
    var_re = re.compile(
        r"^(mapping\s*\(.*\))\s*(.*)$",
        re.DOTALL,
    )
    skip_start = (
        "function ",
        "event ",
        "error ",
        "modifier ",
        "struct ",
        "enum ",
        "constructor",
        "fallback",
        "receive",
        "using ",
        "import ",
        "pragma ",
        "if ",
        "for ",
        "while ",
        "return ",
        "require",
        "revert",
        "emit ",
        "assembly",
        "unchecked",
        "}",
        "{",
    )
    keyword_names = {
        "returns",
        "function",
        "event",
        "error",
        "modifier",
        "struct",
        "enum",
        "mapping",
        "memory",
        "calldata",
        "storage",
        "public",
        "private",
        "internal",
        "external",
        "constant",
        "immutable",
        "override",
        "virtual",
        "payable",
        "pure",
        "view",
    }
    variables: list[StateVariable] = []
    for seg, seg_line_no in segments:
        one_line = re.sub(r"\s+", " ", seg).strip()
        if not one_line or one_line.startswith(skip_start):
            continue
        name = ""
        type_part = ""
        m = var_re.match(one_line)
        if m:
            # mapping type: rest holds "<attrs> <name>"
            rest = m.group(2).split("=")[0].strip()
            bits = rest.rsplit(None, 1)
            if len(bits) != 2:
                continue
            attrs, name = bits
            type_part = f"{m.group(1)} {attrs}".strip()
        else:
            if "(" in one_line or ")" in one_line:
                continue  # function-like or call statement, not a declaration
            decl = one_line.split("=", 1)[0].strip()
            bits = decl.rsplit(None, 1)
            if len(bits) != 2:
                continue
            type_part, name = bits
        if not re.fullmatch(r"[A-Za-z_]\w*", name) or name in keyword_names:
            continue
        if not re.match(r"[A-Za-z_]", type_part.strip()):
            continue
        visibility = "internal"
        for v in ("public", "private", "internal"):
            if re.search(rf"\b{v}\b", type_part):
                visibility = v
                break
        variables.append(
            StateVariable(
                name=name,
                type=re.sub(
                    r"\b(public|private|internal|constant|immutable|override|virtual)\b", "", type_part
                ).strip(),
                visibility=visibility,
                line=seg_line_no,
                constant=bool(re.search(r"\bconstant\b", type_part)),
                immutable=bool(re.search(r"\bimmutable\b", type_part)),
            )
        )
    return variables


def parse_source_file(path: Path, root: Path) -> list[ContractModel]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    clean = strip_comments(text)
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        rel = path.name
    pragma = _PRAGMA_RE.search(clean)
    compiler_version = pragma.group(1).strip() if pragma else ""
    imports = _IMPORT_RE.findall(clean)
    usings = [f"{m.group(1)} for {m.group(2).strip()}" for m in _USING_RE.finditer(clean)]
    models: list[ContractModel] = []
    for match in _CONTRACT_RE.finditer(clean):
        _kind, name = match.group(1), match.group(2)
        parents = [p.strip() for p in (match.group(3) or "").split(",") if p.strip()]
        open_idx = match.end() - 1
        close_idx = _find_matching_brace(clean, open_idx)
        body = clean[open_idx + 1 : close_idx] if close_idx > open_idx else ""
        base_line = clean.count("\n", 0, match.start()) + 1
        functions, calls = _parse_body_functions(body)
        functions = [f.model_copy(update={"line": f.line + base_line}) for f in functions]
        calls = [c.model_copy(update={"contract": c.contract or name, "line": c.line + base_line}) for c in calls]
        events = [
            ContractEvent(
                name=m.group(1),
                params=_split_params(m.group(2) or ""),
                anonymous=bool(m.group(3)),
                line=body.count("\n", 0, m.start()) + base_line + 1,
            )
            for m in _EVENT_RE.finditer(body)
        ]
        errors = [
            ContractError(
                name=m.group(1),
                params=_split_params(m.group(2) or ""),
                line=body.count("\n", 0, m.start()) + base_line + 1,
            )
            for m in _ERROR_RE.finditer(body)
        ]
        modifiers = [
            ContractModifier(
                name=m.group(1),
                params=_split_params((m.group(2) or "").strip("()")),
                line=body.count("\n", 0, m.start()) + base_line + 1,
            )
            for m in _MODIFIER_RE.finditer(body)
        ]
        state_vars = _parse_state_vars(body)
        state_vars = [v.model_copy(update={"line": v.line + base_line}) for v in state_vars]
        interfaces = [p for p in parents if p[:1].isupper() and p.startswith("I")]
        libraries = list({u.split(" for ")[0].strip() for u in usings})
        deps = [Dependency(name=i, kind="import", source=i) for i in imports]
        deps += [Dependency(name=p, kind="inheritance", source=rel) for p in parents]
        models.append(
            ContractModel(
                contract_name=name,
                source_file=rel,
                language="solidity",
                compiler_version=compiler_version,
                interfaces=interfaces,
                libraries=libraries,
                inheritance=parents,
                functions=functions,
                events=events,
                errors=errors,
                state_variables=state_vars,
                modifiers=modifiers,
                imports=list(imports),
                external_dependencies=list({u for u in usings}),
                external_calls=calls,
                dependencies=deps,
            )
        )
    return models


def inventory_contracts(root: Path | str) -> list[ContractModel]:
    root_path = Path(root).resolve()
    from sklab_contract_toolkit.standards.categories import classify_contract
    from sklab_contract_toolkit.standards.registry import detect_standards

    models: list[ContractModel] = []
    for path in iter_project_files(root_path, (".sol",)):
        models.extend(parse_source_file(path, root_path))
    # Enrich with standards + category (lazy import to avoid cycles)
    for model in models:
        try:
            model.standards = [s.model_dump() for s in detect_standards(model)]
            model.category = classify_contract(model)
        except Exception:
            continue
    return models


def extract_abis(root: Path | str) -> dict[str, Any]:
    """Build ABI-like JSON per contract from source (functions/events/errors)."""
    root_path = Path(root).resolve()
    abis: dict[str, Any] = {}
    for model in inventory_contracts(root_path):
        entries: list[dict[str, Any]] = []
        for fn in model.functions:
            if fn.name in ("constructor", "fallback", "receive"):
                entry_type = {"constructor": "constructor", "fallback": "fallback", "receive": "receive"}[fn.name]
                entries.append(
                    {
                        "type": entry_type,
                        "name": fn.name,
                        "inputs": [dict(type=t) for t in _param_types(fn.params)],
                        "stateMutability": fn.mutability,
                    }
                )
            else:
                entries.append(
                    {
                        "type": "function",
                        "name": fn.name,
                        "inputs": [dict(type=t) for t in _param_types(fn.params)],
                        "outputs": [dict(type=t) for t in _param_types(fn.returns)],
                        "stateMutability": fn.mutability,
                        "selector": fn.selector,
                    }
                )
        for ev in model.events:
            entries.append(
                {
                    "type": "event",
                    "name": ev.name,
                    "inputs": [dict(type=t) for t in _param_types(ev.params)],
                    "anonymous": ev.anonymous,
                }
            )
        for er in model.errors:
            entries.append(
                {"type": "error", "name": er.name, "inputs": [dict(type=t) for t in _param_types(er.params)]}
            )
        abis[model.contract_name] = {"contract": model.contract_name, "source": model.source_file, "abi": entries}
    return abis


def load_abi_file(path: Path) -> dict[str, Any]:
    """Load a raw ABI JSON file (array or {"abi": [...]} or artifact with abi key)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {"abi": data}
    if isinstance(data, dict) and "abi" in data:
        abi = data["abi"]
        if isinstance(abi, dict) and "abi" in abi:
            abi = abi["abi"]
        return {"abi": abi if isinstance(abi, list) else []}
    return {"abi": []}
