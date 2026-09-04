"""Project-level models: detection results, inventory, toolchain metadata."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ProjectKind = Literal["foundry", "hardhat", "raw_solidity", "mixed_solidity", "truffle_legacy", "unknown"]
ChainId = Literal["evm", "solana", "move-aptos", "move-sui", "cosmwasm", "ton", "unknown"]


class DetectionEvidence(BaseModel):
    signal: str
    weight: float = 1.0
    detail: str = ""


class ProjectDetection(BaseModel):
    kind: str = "unknown"
    chain: str = "evm"
    confidence: float = 0.0
    evidence: list[DetectionEvidence] = Field(default_factory=list)
    root: str = ""
    toolchain: str = "auto"
    notes: list[str] = Field(default_factory=list)


class AuthorityRecord(BaseModel):
    authority: str
    capability: str = ""
    target_contract: str = ""
    evidence: str = ""
    confidence: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"


class StandardMatch(BaseModel):
    standard: str
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class EnvironmentMetadata(BaseModel):
    os: str = ""
    python_version: str = ""
    tools: dict[str, str] = Field(default_factory=dict)
    fingerprint: str = ""
    offline: bool = False
    local_only: bool = False
