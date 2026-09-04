"""Future-ready chain adapter stubs. Never claim support that is not implemented.

All non-EVM adapters report EXPERIMENTAL or UNAVAILABLE honestly. They exist
so the registry, CLI, and plugin API are future-compatible without code
changes to the public core.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sklab_contract_toolkit.chains.base import AdapterState, ChainAdapter


class _FutureAdapter(ChainAdapter):
    _capabilities: dict[str, bool] | None = None

    def detect_project(self, root: Path) -> dict[str, Any]:
        return {"chain": self.chain_id, "state": self.state.value, "kind": "unknown", "confidence": 0.0}

    def detect_sources(self, root: Path) -> list[str]:
        return []

    def detect_artifacts(self, root: Path) -> list[str]:
        return []

    def detect_contracts(self, root: Path) -> list[dict[str, Any]]:
        return []

    def capabilities(self) -> dict[str, bool]:
        return {
            "detect_project": False,
            "detect_sources": False,
            "detect_artifacts": False,
            "detect_contracts": False,
            "compile": False,
            "test": False,
            "analyze": False,
            "extract_abi": False,
            "extract_storage": False,
            "extract_authorities": False,
            "extract_upgradeability": False,
            "normalize_findings": True,
        }

    def tool_requirements(self) -> list[str]:
        return []


class SolanaAdapter(_FutureAdapter):
    chain_id = "solana"
    state = AdapterState.EXPERIMENTAL

    def tool_requirements(self) -> list[str]:
        return ["anchor", "cargo", "solana-cli"]


class MoveAptosAdapter(_FutureAdapter):
    chain_id = "move-aptos"
    state = AdapterState.EXPERIMENTAL

    def tool_requirements(self) -> list[str]:
        return ["aptos-cli"]


class MoveSuiAdapter(_FutureAdapter):
    chain_id = "move-sui"
    state = AdapterState.EXPERIMENTAL

    def tool_requirements(self) -> list[str]:
        return ["sui-cli"]


class CosmWasmAdapter(_FutureAdapter):
    chain_id = "cosmwasm"
    state = AdapterState.EXPERIMENTAL

    def tool_requirements(self) -> list[str]:
        return ["cargo", "wasmd"]


class TonAdapter(_FutureAdapter):
    chain_id = "ton"
    state = AdapterState.UNAVAILABLE

    def tool_requirements(self) -> list[str]:
        return ["ton-cli", "func"]
