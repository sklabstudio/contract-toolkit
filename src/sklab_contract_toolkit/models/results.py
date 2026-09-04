"""Normalized result models for test / fuzz / invariant / gas / coverage."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class TestSummary(BaseModel):
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    duration_seconds: float = 0.0
    failures: list[str] = Field(default_factory=list)
    tool: str = ""
    raw_output: str = ""


class FuzzResult(BaseModel):
    target: str = ""
    seed: str = ""
    runs: int = 0
    failures: int = 0
    counterexample: str = ""
    tool: str = ""
    tool_version: str = ""
    reproducible: bool = False
    raw_output: str = ""


class InvariantResult(BaseModel):
    property: str
    status: Literal["PASS", "FAIL", "INCONCLUSIVE"] = "INCONCLUSIVE"
    runs: int = 0
    depth: int = 0
    counterexample: str = ""
    tool: str = ""


class GasEntry(BaseModel):
    contract: str = ""
    function: str = ""
    mean_gas: int = 0
    notes: str = ""


class GasReport(BaseModel):
    tool: str = ""
    entries: list[GasEntry] = Field(default_factory=list)
    hotspots: list[str] = Field(default_factory=list)
    regressions: list[str] = Field(default_factory=list)
    raw_output: str = ""


class CoverageReport(BaseModel):
    tool: str = ""
    line: float = 0.0
    branch: float = 0.0
    function: float = 0.0
    statement: float = 0.0
    files: list[dict[str, Any]] = Field(default_factory=list)
    raw_output: str = ""


class StorageSlot(BaseModel):
    slot: str = ""
    offset: int = 0
    type: str = ""
    label: str = ""
    contract: str = ""


class StorageLayout(BaseModel):
    contract: str = ""
    slots: list[StorageSlot] = Field(default_factory=list)
    source: str = ""  # solc-metadata | foundry-artifact | hardhat-artifact | heuristic


class AbiDiff(BaseModel):
    added_functions: list[str] = Field(default_factory=list)
    removed_functions: list[str] = Field(default_factory=list)
    changed_selectors: list[str] = Field(default_factory=list)
    added_events: list[str] = Field(default_factory=list)
    removed_events: list[str] = Field(default_factory=list)
    added_errors: list[str] = Field(default_factory=list)
    removed_errors: list[str] = Field(default_factory=list)
    mutability_changes: list[str] = Field(default_factory=list)
    breaking: bool = False


class UpgradeVerdict(BaseModel):
    verdict: Literal["SAFE", "RISKY", "INCOMPATIBLE", "INCONCLUSIVE"] = "INCONCLUSIVE"
    proxy_pattern: str = ""
    evidence: list[str] = Field(default_factory=list)
    storage_added: list[str] = Field(default_factory=list)
    storage_removed: list[str] = Field(default_factory=list)
    storage_type_changes: list[str] = Field(default_factory=list)
    authorization_changes: list[str] = Field(default_factory=list)


class VerificationResult(BaseModel):
    status: Literal["FIXED_VERIFIED", "FIXED_UNVERIFIED", "NOT_FIXED", "REGRESSION", "INCONCLUSIVE"] = "INCONCLUSIVE"
    evidence: list[str] = Field(default_factory=list)
    checks: dict[str, str] = Field(default_factory=dict)
