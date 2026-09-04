"""Stable public Python API (Orchestrator / Web UI must not parse CLI text)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sklab_contract_toolkit.analysis.engine import run_internal_analysis
from sklab_contract_toolkit.analysis.remediation import prepare_fix, verify_fix
from sklab_contract_toolkit.analysis.slither_norm import run_slither
from sklab_contract_toolkit.core.config import ToolkitConfig
from sklab_contract_toolkit.core.pathsafety import resolve_root
from sklab_contract_toolkit.detection.project import detect_project
from sklab_contract_toolkit.detection.solidity import inventory_contracts
from sklab_contract_toolkit.models.findings import deduplicate_findings
from sklab_contract_toolkit.reports.builder import build_report_bundle
from sklab_contract_toolkit.testing.flows import (
    compile_project,
    run_fuzz,
    run_invariants,
    run_tests,
)
from sklab_contract_toolkit.upgrades.abi_diff import diff_abi_files
from sklab_contract_toolkit.upgrades.review import review_upgrade
from sklab_contract_toolkit.upgrades.storage import diff_storage, extract_storage_layouts
from sklab_contract_toolkit.version import __version__


class ContractToolkit:
    """Typed SDK entry point."""

    def __init__(self, config: ToolkitConfig | None = None, root: Path | str = ".") -> None:
        self.root = Path(root).resolve()
        self.config = config or ToolkitConfig()

    # -- project ---------------------------------------------------------
    def detect_project(self, path: Path | str | None = None) -> dict[str, Any]:
        return detect_project(Path(path) if path else self.root).model_dump()

    def list_contracts(self, path: Path | str | None = None) -> list[dict[str, Any]]:
        root = resolve_root(Path(path) if path else self.root)
        return [m.model_dump() for m in inventory_contracts(root)]

    def inspect_contract(
        self, path: Path | str | None = None, abi: str | None = None, bytecode: str | None = None
    ) -> dict[str, Any]:
        from sklab_contract_toolkit.cli import build_inspection

        return build_inspection(Path(path) if path else self.root, abi_path=abi, bytecode_path=bytecode)

    def list_tools(self) -> list[dict[str, Any]]:
        from sklab_contract_toolkit.tools.manager import tools_json

        return tools_json()

    # -- flows -----------------------------------------------------------
    def compile_project(self, path: Path | str | None = None) -> dict[str, Any]:
        return compile_project(Path(path) if path else self.root)

    def run_tests(self, path: Path | str | None = None) -> dict[str, Any]:
        return run_tests(Path(path) if path else self.root).model_dump()

    def run_fuzz(self, path: Path | str | None = None, runs: int = 256, seed: str = "0") -> list[dict[str, Any]]:
        return [f.model_dump() for f in run_fuzz(Path(path) if path else self.root, runs=runs, seed=seed)]

    def run_invariants(self, path: Path | str | None = None) -> list[dict[str, Any]]:
        return [i.model_dump() for i in run_invariants(Path(path) if path else self.root)]

    def run_analysis(self, path: Path | str | None = None, include_slither: bool = True) -> list[dict[str, Any]]:
        root = resolve_root(Path(path) if path else self.root)
        findings = run_internal_analysis(root)
        if include_slither:
            slither = run_slither(root)
            findings.extend(slither.get("findings", []))
        return [f.model_dump() for f in deduplicate_findings(findings)]

    def review_upgrade(self, old: Path | str, new: Path | str) -> dict[str, Any]:
        return review_upgrade(old, new).model_dump()

    def diff_storage(self, old: Path | str, new: Path | str, contract: str | None = None) -> dict[str, Any]:
        old_layouts = extract_storage_layouts(old)
        new_layouts = extract_storage_layouts(new)
        names = [contract] if contract else sorted(set(old_layouts) | set(new_layouts))
        return {n: diff_storage(old_layouts[n], new_layouts[n]) for n in names if n in old_layouts and n in new_layouts}

    def diff_abi(self, old: Path | str, new: Path | str) -> dict[str, Any]:
        return diff_abi_files(old, new).model_dump()

    def generate_report(self, path: Path | str | None = None) -> dict[str, Any]:
        from sklab_contract_toolkit.cli import build_inspection

        root = resolve_root(Path(path) if path else self.root)
        inspection = build_inspection(root)
        findings = [f.model_dump() for f in deduplicate_findings(run_internal_analysis(root))]
        return build_report_bundle(
            root,
            contracts=inspection["contracts"],
            standards=inspection["standards"],
            authorities=inspection["authorities"],
            findings=findings,
            project=inspection["project"],
        )

    def prepare_fix(
        self, ref: str, path: Path | str | None = None, out_dir: Path | str | None = None
    ) -> dict[str, Any]:
        return prepare_fix(ref, Path(path) if path else self.root, out_dir=out_dir)

    def verify_fix(self, ref: str, path: Path | str | None = None) -> dict[str, Any]:
        return verify_fix(ref, Path(path) if path else self.root).model_dump()

    def version(self) -> str:
        return __version__
