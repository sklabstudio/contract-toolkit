"""Public semantic contract model — open, deterministic facts only.

This is NOT a proprietary semantic intelligence engine. It captures
practical facts extracted deterministically from source / ABI / artifacts:
contracts, functions, state variables, events, modifiers, roles,
external calls, asset references, upgrade references, dependencies.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Visibility(StrEnum):
    PUBLIC = "public"
    EXTERNAL = "external"
    INTERNAL = "internal"
    PRIVATE = "private"


class Mutability(StrEnum):
    PURE = "pure"
    VIEW = "view"
    NONPAYABLE = "nonpayable"
    PAYABLE = "payable"


class ContractFunction(BaseModel):
    name: str
    visibility: str = "public"
    mutability: str = "nonpayable"
    params: list[str] = Field(default_factory=list)
    returns: list[str] = Field(default_factory=list)
    modifiers: list[str] = Field(default_factory=list)
    line: int = 0
    selector: str = ""


class StateVariable(BaseModel):
    name: str
    type: str = ""
    visibility: str = "internal"
    line: int = 0
    constant: bool = False
    immutable: bool = False


class ContractEvent(BaseModel):
    name: str
    params: list[str] = Field(default_factory=list)
    anonymous: bool = False
    line: int = 0


class ContractError(BaseModel):
    name: str
    params: list[str] = Field(default_factory=list)
    line: int = 0


class ContractModifier(BaseModel):
    name: str
    params: list[str] = Field(default_factory=list)
    line: int = 0


class Role(BaseModel):
    name: str
    kind: str = "custom"  # owner | admin | role-constant | modifier | multisig | timelock | ...
    contract: str = ""
    evidence: str = ""
    confidence: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"


class ExternalCall(BaseModel):
    contract: str = ""
    function: str = ""
    target: str = ""  # address expression or contract name
    line: int = 0
    low_level: bool = False
    evidence: str = ""


class AssetReference(BaseModel):
    kind: str = "token"  # token | ether | nft | ...
    reference: str = ""
    contract: str = ""
    line: int = 0


class UpgradeReference(BaseModel):
    pattern: str = ""  # UUPS | Transparent | Beacon | Diamond | custom
    contract: str = ""
    evidence: str = ""
    line: int = 0


class Dependency(BaseModel):
    name: str
    kind: str = "import"  # import | inheritance | library | interface
    source: str = ""


class ContractModel(BaseModel):
    contract_name: str
    source_file: str
    language: str = "solidity"
    compiler_version: str = ""
    interfaces: list[str] = Field(default_factory=list)
    libraries: list[str] = Field(default_factory=list)
    inheritance: list[str] = Field(default_factory=list)
    functions: list[ContractFunction] = Field(default_factory=list)
    events: list[ContractEvent] = Field(default_factory=list)
    errors: list[ContractError] = Field(default_factory=list)
    state_variables: list[StateVariable] = Field(default_factory=list)
    modifiers: list[ContractModifier] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    external_dependencies: list[str] = Field(default_factory=list)
    roles: list[Role] = Field(default_factory=list)
    external_calls: list[ExternalCall] = Field(default_factory=list)
    asset_references: list[AssetReference] = Field(default_factory=list)
    upgrade_references: list[UpgradeReference] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)
    standards: list[dict[str, Any]] = Field(default_factory=list)
    category: str = "CUSTOM"
    authorities: list[dict[str, Any]] = Field(default_factory=list)
