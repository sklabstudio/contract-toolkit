"""Typed configuration for sklab-contract.yaml (Pydantic v2, strict)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError


class ProjectConfig(BaseModel):
    chain: str = "auto"
    toolchain: str = "auto"
    root: str = "."


class EvmConfig(BaseModel):
    preferred_toolchain: Literal["foundry", "hardhat", "solc", "auto"] = "foundry"


class AnalysisConfig(BaseModel):
    static: bool = True
    fuzz: bool = True
    invariants: bool = True
    timeout_seconds: int = Field(default=300, ge=1, le=7200)


class ToolsConfig(BaseModel):
    slither: str = "auto"
    echidna: str = "auto"
    mythril: str = "auto"
    halmos: str = "auto"
    aderyn: str = "auto"
    solhint: str = "auto"


class NetworkConfig(BaseModel):
    allow_readonly_rpc: bool = False


class RemediationConfig(BaseModel):
    isolated: bool = True
    require_verification: bool = True


class ToolkitConfig(BaseModel):
    schema_version: Literal[1] = 1
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    evm: EvmConfig = Field(default_factory=EvmConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    remediation: RemediationConfig = Field(default_factory=RemediationConfig)
    chains: dict[str, dict[str, str]] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


CONFIG_FILENAMES = ("sklab-contract.yaml", "sklab-contract.yml", ".sklab-contract.yaml")


def find_config(start: Path) -> Path | None:
    current = start.resolve()
    while True:
        for name in CONFIG_FILENAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
        parent = current.parent
        if parent == current:
            return None
        current = parent


def load_config(path: Path | str | None = None, start: Path | None = None) -> ToolkitConfig:
    """Load and strictly validate configuration. Raises ValidationError on bad config."""
    if path is not None:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Config file not found: {p}")
        data: Any = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return ToolkitConfig.model_validate(data)
    base = (start or Path.cwd()).resolve()
    direct = base / "sklab-contract.yaml"
    if direct.is_file():
        data = yaml.safe_load(direct.read_text(encoding="utf-8")) or {}
        return ToolkitConfig.model_validate(data)
    found = find_config(base)
    if found is None:
        return ToolkitConfig()
    data = yaml.safe_load(found.read_text(encoding="utf-8")) or {}
    return ToolkitConfig.model_validate(data)


def config_validation_errors(data: dict[str, Any]) -> list[str]:
    try:
        ToolkitConfig.model_validate(data)
        return []
    except ValidationError as exc:
        return [f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in exc.errors()]
