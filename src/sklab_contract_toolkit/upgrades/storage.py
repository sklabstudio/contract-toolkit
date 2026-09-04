"""Storage layout extraction + deterministic diff.

Sources: solc standard-json storageLayout (when available), Foundry/Hardhat
artifacts, and deterministic source heuristics as fallback.
"""

from __future__ import annotations

import json
from pathlib import Path

from sklab_contract_toolkit.core.pathsafety import resolve_root
from sklab_contract_toolkit.detection.solidity import inventory_contracts
from sklab_contract_toolkit.models.results import StorageLayout, StorageSlot

_TYPE_SLOTS: dict[str, int] = {
    "bool": 1,
    "address": 1,
    "uint": 1,
    "uint8": 1,
    "uint256": 1,
    "int256": 1,
    "bytes32": 1,
    "string": 1,
    "bytes": 1,
}


def _heuristic_layout(contract: str, source_file: str, state_vars: list[dict]) -> StorageLayout:
    slots: list[StorageSlot] = []
    slot = 0
    for var in state_vars:
        vtype = (var.get("type") or "").strip()
        label = var.get("name", "")
        if var.get("constant") or var.get("immutable"):
            continue  # constants/immutables do not occupy storage
        slots.append(StorageSlot(slot=str(slot), offset=0, type=vtype or "unknown", label=label, contract=contract))
        slot += 1
    return StorageLayout(contract=contract, slots=slots, source="heuristic")


def extract_storage_layouts(root: Path | str) -> dict[str, StorageLayout]:
    root_path = resolve_root(root)
    layouts: dict[str, StorageLayout] = {}
    # 1) artifacts with storageLayout
    for base in ("artifacts", "out", "cache"):
        d = root_path / base
        if not d.is_dir():
            continue
        for artifact in d.rglob("*.json"):
            try:
                data = json.loads(artifact.read_text(encoding="utf-8"))
            except Exception:
                continue
            for key in ("storageLayout",):
                layout = data.get(key) if isinstance(data, dict) else None
                if isinstance(layout, dict) and layout.get("storage"):
                    name = data.get("contractName") or artifact.stem
                    slots = [
                        StorageSlot(
                            slot=str(s.get("slot", "")),
                            offset=int(s.get("offset", 0)),
                            type=str(s.get("type", "")),
                            label=str(s.get("label", "")),
                            contract=str(name),
                        )
                        for s in layout["storage"]
                    ]
                    layouts[str(name)] = StorageLayout(
                        contract=str(name), slots=slots, source="artifact:" + artifact.name
                    )
    # 2) heuristic from source for contracts not covered
    for model in inventory_contracts(root_path):
        if model.contract_name not in layouts:
            layouts[model.contract_name] = _heuristic_layout(
                model.contract_name, model.source_file, [v.model_dump() for v in model.state_variables]
            )
    return layouts


def diff_storage(old: StorageLayout, new: StorageLayout) -> dict[str, list[str]]:
    old_vars = [(s.label, s.type) for s in old.slots]
    new_vars = [(s.label, s.type) for s in new.slots]
    old_labels = [label for label, _ in old_vars]
    new_labels = [label for label, _ in new_vars]
    added = [label for label in new_labels if label not in old_labels]
    removed = [label for label in old_labels if label not in new_labels]
    type_changes: list[str] = []
    reorder: list[str] = []
    common_old = [label for label in old_labels if label in new_labels]
    common_new = [label for label in new_labels if label in old_labels]
    if common_old != common_new:
        reorder.append(f"variable order changed: {common_old} -> {common_new}")
    old_types = {label: t for label, t in old_vars}
    new_types = {label: t for label, t in new_vars}
    for label in common_old:
        if old_types.get(label) != new_types.get(label):
            type_changes.append(f"{label}: {old_types.get(label)} -> {new_types.get(label)}")

    # detect slot shifts by absolute position (insertions shift later variables)
    def _positions(layout: StorageLayout) -> dict[str, str]:
        pos: dict[str, str] = {}
        for i, s in enumerate(layout.slots):
            pos.setdefault(s.label, f"{s.slot or i}:{s.offset}")
        return pos

    old_pos, new_pos = _positions(old), _positions(new)
    shifted: list[str] = []
    for label in common_old:
        if old_pos.get(label) != new_pos.get(label):
            shifted.append(f"{label} moved {old_pos.get(label)} -> {new_pos.get(label)}")
    return {
        "added": added,
        "removed": removed,
        "type_changes": type_changes,
        "order_changed": reorder,
        "shifted": shifted,
    }
