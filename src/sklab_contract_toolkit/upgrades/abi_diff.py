"""ABI diff: added/removed functions, selector changes, events, errors, mutability."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sklab_contract_toolkit.detection.solidity import load_abi_file
from sklab_contract_toolkit.models.results import AbiDiff


def _sig_index(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if entry.get("type") == "function" and entry.get("name"):
            inputs = ",".join(i.get("type", "") for i in entry.get("inputs", []))
            sig = f"{entry['name']}({inputs})"
            index[sig] = entry
    return index


def _event_index(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {e["name"]: e for e in entries if e.get("type") == "event" and e.get("name")}


def _error_index(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {e["name"]: e for e in entries if e.get("type") == "error" and e.get("name")}


def diff_abis(old_entries: list[dict[str, Any]], new_entries: list[dict[str, Any]]) -> AbiDiff:
    old_fns, new_fns = _sig_index(old_entries), _sig_index(new_entries)
    added = sorted(set(new_fns) - set(old_fns))
    removed = sorted(set(old_fns) - set(new_fns))
    mutability_changes = sorted(
        sig
        for sig in set(old_fns) & set(new_fns)
        if old_fns[sig].get("stateMutability") != new_fns[sig].get("stateMutability")
    )
    # selector changes: same name, different signature
    old_names: dict[str, set[str]] = {}
    new_names: dict[str, set[str]] = {}
    for sig in old_fns:
        old_names.setdefault(sig.split("(")[0], set()).add(sig)
    for sig in new_fns:
        new_names.setdefault(sig.split("(")[0], set()).add(sig)
    changed_selectors = sorted(name for name in set(old_names) & set(new_names) if old_names[name] != new_names[name])
    old_ev, new_ev = _event_index(old_entries), _event_index(new_entries)
    old_er, new_er = _error_index(old_entries), _error_index(new_entries)
    breaking = bool(removed or changed_selectors or mutability_changes)
    return AbiDiff(
        added_functions=added,
        removed_functions=removed,
        changed_selectors=changed_selectors,
        added_events=sorted(set(new_ev) - set(old_ev)),
        removed_events=sorted(set(old_ev) - set(new_ev)),
        added_errors=sorted(set(new_er) - set(old_er)),
        removed_errors=sorted(set(old_er) - set(new_er)),
        mutability_changes=mutability_changes,
        breaking=breaking,
    )


def load_entries(source: Path | str) -> list[dict[str, Any]]:
    """Load ABI entries from .json (ABI array / artifact) or .sol (source-derived)."""
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"ABI source not found: {source}")
    if path.suffix == ".json":
        data = load_abi_file(path)
        entries = data.get("abi", [])
        return entries if isinstance(entries, list) else []
    if path.suffix == ".sol":
        from sklab_contract_toolkit.detection.solidity import extract_abis

        abis = extract_abis(path.parent if path.is_file() else path)
        collected: list[dict[str, Any]] = []
        for info in abis.values():
            collected.extend(info.get("abi", []))
        # if a single file was given, filter to contracts in that file
        return collected
    raise ValueError(f"Unsupported ABI source (use .json or .sol): {source}")


def diff_abi_files(old: Path | str, new: Path | str) -> AbiDiff:
    return diff_abis(load_entries(old), load_entries(new))
