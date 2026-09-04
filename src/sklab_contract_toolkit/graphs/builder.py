"""Public structural graphs: inheritance, import, call, dependency,
external-call, and authority/role graphs. Export JSON / DOT / Mermaid.
No rendering required.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sklab_contract_toolkit.analysis.authorities import extract_authorities
from sklab_contract_toolkit.core.pathsafety import resolve_root
from sklab_contract_toolkit.detection.solidity import inventory_contracts


def build_graphs(root: Path | str) -> dict[str, dict[str, list[Any]]]:
    root_path = resolve_root(root)
    models = inventory_contracts(root_path)
    inheritance_edges: list[list[str]] = []
    import_edges: list[list[str]] = []
    call_edges: list[list[str]] = []
    dependency_edges: list[list[str]] = []
    external_edges: list[list[str]] = []
    for model in models:
        for parent in model.inheritance:
            inheritance_edges.append([model.contract_name, parent])
            dependency_edges.append([model.contract_name, parent])
        for imp in model.imports:
            import_edges.append([model.contract_name, imp])
            dependency_edges.append([model.contract_name, imp])
        for fn in model.functions:
            for mod in fn.modifiers:
                call_edges.append([f"{model.contract_name}.{fn.name}", f"modifier:{mod}"])
        for call in model.external_calls:
            target = call.contract or call.target or "external"
            external_edges.append([f"{model.contract_name}", f"{target}.{call.function}"])
            call_edges.append([model.contract_name, f"{target}.{call.function}"])
    authorities = extract_authorities(root_path)
    authority_edges: list[list[str]] = [[a.authority, a.target_contract] for a in authorities]
    nodes = sorted({m.contract_name for m in models})
    return {
        "inheritance": {"nodes": nodes, "edges": sorted(inheritance_edges)},
        "import": {"nodes": nodes, "edges": sorted(import_edges)},
        "call": {"nodes": nodes, "edges": sorted(call_edges)},
        "dependency": {"nodes": nodes, "edges": sorted(dependency_edges)},
        "external_call": {"nodes": nodes, "edges": sorted(external_edges)},
        "authority": {
            "nodes": sorted({a.authority for a in authorities} | set(nodes)),
            "edges": sorted(authority_edges),
        },
    }


def to_dot(name: str, graph: dict[str, list[Any]]) -> str:
    lines = [f'digraph "{name}" {{', '  rankdir="LR";']
    for node in graph.get("nodes", []):
        lines.append(f'  "{node}";')
    for edge in graph.get("edges", []):
        if len(edge) >= 2:
            lines.append(f'  "{edge[0]}" -> "{edge[1]}";')
    lines.append("}")
    return "\n".join(lines) + "\n"


def to_mermaid(name: str, graph: dict[str, list[Any]]) -> str:
    lines = ["graph LR"]
    safe = re_safe(name)
    lines.append(f"  %% {safe}")
    for edge in graph.get("edges", []):
        if len(edge) >= 2:
            lines.append(f"  {re_safe(str(edge[0]))} --> {re_safe(str(edge[1]))}")
    if not graph.get("edges"):
        for node in graph.get("nodes", []):
            lines.append(f"  {re_safe(str(node))}")
    return "\n".join(lines) + "\n"


def re_safe(text: str) -> str:
    import re as _re

    return _re.sub(r"[^A-Za-z0-9_]", "_", text)
