"""EVM / Solidity chain adapter — FULL support in v0.1.0."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sklab_contract_toolkit.analysis.authorities import extract_authorities
from sklab_contract_toolkit.analysis.engine import run_internal_analysis
from sklab_contract_toolkit.chains.base import AdapterState, ChainAdapter
from sklab_contract_toolkit.detection.project import detect_project
from sklab_contract_toolkit.detection.solidity import inventory_contracts
from sklab_contract_toolkit.upgrades.storage import extract_storage_layouts


class EvmAdapter(ChainAdapter):
    chain_id = "evm"
    state = AdapterState.SUPPORTED

    def detect_project(self, root: Path) -> dict[str, Any]:
        detection = detect_project(root)
        return detection.model_dump()

    def detect_sources(self, root: Path) -> list[str]:
        root = root.resolve()
        out: list[str] = []
        for pattern in ("*.sol",):
            for path in sorted(root.rglob(pattern)):
                if ".git" in path.parts or "node_modules" in path.parts or "lib" in path.parts:
                    continue
                try:
                    out.append(path.relative_to(root).as_posix())
                except ValueError:
                    continue
        return out

    def detect_artifacts(self, root: Path) -> list[str]:
        root = root.resolve()
        out: list[str] = []
        for base in ("artifacts", "out", "cache"):
            d = root / base
            if d.is_dir():
                for path in sorted(d.rglob("*.json")):
                    try:
                        out.append(path.relative_to(root).as_posix())
                    except ValueError:
                        continue
        return out

    def detect_contracts(self, root: Path) -> list[dict[str, Any]]:
        return [c.model_dump() for c in inventory_contracts(root)]

    def analyze(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        findings = run_internal_analysis(root)
        return {"findings": [f.model_dump() for f in findings]}

    def extract_abi(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        from sklab_contract_toolkit.detection.solidity import extract_abis

        return extract_abis(root)

    def extract_storage(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        layouts = extract_storage_layouts(root)
        return {name: layout.model_dump() for name, layout in layouts.items()}

    def extract_authorities(self, root: Path, **kwargs: Any) -> list[dict[str, Any]]:
        return [a.model_dump() for a in extract_authorities(root)]

    def extract_upgradeability(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        from sklab_contract_toolkit.upgrades.review import summarize_upgradeability

        return summarize_upgradeability(root)

    def normalize_findings(self, raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
        from sklab_contract_toolkit.models.findings import ContractFinding, deduplicate_findings

        findings = [ContractFinding.model_validate(r).with_fingerprint() for r in raw]
        return [f.model_dump() for f in deduplicate_findings(findings)]

    def capabilities(self) -> dict[str, bool]:
        return {
            "detect_project": True,
            "detect_sources": True,
            "detect_artifacts": True,
            "detect_contracts": True,
            "compile": True,
            "test": True,
            "analyze": True,
            "extract_abi": True,
            "extract_storage": True,
            "extract_authorities": True,
            "extract_upgradeability": True,
            "normalize_findings": True,
            "fuzz": True,
            "invariants": True,
            "gas": True,
            "coverage": True,
            "local_fork": True,
        }

    def tool_requirements(self) -> list[str]:
        return ["solc", "foundry", "anvil", "hardhat", "slither"]
