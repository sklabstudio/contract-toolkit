"""Stable chain-adapter interface shared by EVM and future non-EVM chains."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from pathlib import Path
from typing import Any


class AdapterState(StrEnum):
    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    EXPERIMENTAL = "EXPERIMENTAL"
    UNAVAILABLE = "UNAVAILABLE"


class ChainAdapter(ABC):
    """Generic chain-adapter contract. Never fake support: report state honestly."""

    chain_id: str = "unknown"
    state: AdapterState = AdapterState.UNAVAILABLE

    @abstractmethod
    def detect_project(self, root: Path) -> dict[str, Any]: ...

    @abstractmethod
    def detect_sources(self, root: Path) -> list[str]: ...

    @abstractmethod
    def detect_artifacts(self, root: Path) -> list[str]: ...

    @abstractmethod
    def detect_contracts(self, root: Path) -> list[dict[str, Any]]: ...

    def compile(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        raise NotImplementedError(f"{self.chain_id} compile not implemented")

    def test(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        raise NotImplementedError(f"{self.chain_id} test not implemented")

    def analyze(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        raise NotImplementedError(f"{self.chain_id} analyze not implemented")

    def extract_abi(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        raise NotImplementedError(f"{self.chain_id} extract_abi not implemented")

    def extract_storage(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        raise NotImplementedError(f"{self.chain_id} extract_storage not implemented")

    def extract_authorities(self, root: Path, **kwargs: Any) -> list[dict[str, Any]]:
        raise NotImplementedError(f"{self.chain_id} extract_authorities not implemented")

    def extract_upgradeability(self, root: Path, **kwargs: Any) -> dict[str, Any]:
        raise NotImplementedError(f"{self.chain_id} extract_upgradeability not implemented")

    def normalize_findings(self, raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return list(raw)

    @abstractmethod
    def capabilities(self) -> dict[str, bool]: ...

    @abstractmethod
    def tool_requirements(self) -> list[str]: ...
