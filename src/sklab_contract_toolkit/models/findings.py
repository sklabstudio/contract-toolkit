"""Normalized finding model: ContractFinding."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel

from sklab_contract_toolkit.core.fingerprints import finding_fingerprint

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Confidence = Literal["LOW", "MEDIUM", "HIGH"]
FindingStatus = Literal["OPEN", "FIXED_VERIFIED", "FIXED_UNVERIFIED", "NOT_FIXED", "REGRESSION", "INCONCLUSIVE"]
EvidenceLevel = Literal["CONFIRMED", "HEURISTIC", "TOOL_REPORTED", "INCONCLUSIVE"]


class FindingCategory(StrEnum):
    ACCESS_CONTROL = "ACCESS_CONTROL"
    REENTRANCY = "REENTRANCY"
    EXTERNAL_CALL = "EXTERNAL_CALL"
    SIGNATURE = "SIGNATURE"
    REPLAY = "REPLAY"
    ARITHMETIC = "ARITHMETIC"
    ROUNDING = "ROUNDING"
    TOKEN_ACCOUNTING = "TOKEN_ACCOUNTING"
    UPGRADEABILITY = "UPGRADEABILITY"
    STORAGE = "STORAGE"
    INITIALIZATION = "INITIALIZATION"
    ORACLE = "ORACLE"
    FRONTRUNNING = "FRONTRUNNING"
    MEV_SENSITIVE = "MEV_SENSITIVE"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    GAS = "GAS"
    EVENTS = "EVENTS"
    AUTHORITY = "AUTHORITY"
    UNSAFE_DELEGATECALL = "UNSAFE_DELEGATECALL"
    SELFDESTRUCT = "SELFDESTRUCT"
    TX_ORIGIN = "TX_ORIGIN"
    UNCHECKED_RETURN = "UNCHECKED_RETURN"
    APPROVAL = "APPROVAL"
    CONFIGURATION = "CONFIGURATION"
    TEST_COVERAGE = "TEST_COVERAGE"
    CUSTOM = "CUSTOM"


class ContractFinding(BaseModel):
    id: str = ""
    rule_id: str
    rule_version: str = "1.0.0"
    title: str
    category: str = FindingCategory.CUSTOM.value
    severity: Severity = "INFO"
    confidence: Confidence = "MEDIUM"
    evidence_level: EvidenceLevel = "HEURISTIC"
    status: FindingStatus = "OPEN"
    contract: str = ""
    function: str = ""
    file: str = ""
    line: int = 0
    description: str = ""
    evidence: str = ""
    cwe: str = ""
    swc: str = ""
    tool: str = "sklab-internal"
    tool_rule: str = ""
    recommendation: str = ""
    fingerprint: str = ""

    def with_fingerprint(self) -> ContractFinding:
        if not self.fingerprint:
            self.fingerprint = finding_fingerprint(
                self.rule_id,
                self.rule_version,
                self.contract,
                self.function,
                self.file,
                self.line,
                self.title,
            )
        if not self.id:
            self.id = f"{self.rule_id}-{self.fingerprint[:12]}"
        return self


def deduplicate_findings(findings: list[ContractFinding]) -> list[ContractFinding]:
    """Deduplicate by fingerprint, preferring internal-tool evidence ties deterministically."""
    for f in findings:
        f.with_fingerprint()
    best: dict[str, ContractFinding] = {}
    for f in findings:
        key = f.fingerprint
        if key not in best:
            best[key] = f
            continue
        # Prefer higher confidence deterministically
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        if order.get(f.confidence, 0) > order.get(best[key].confidence, 0):
            # merge tool provenance
            f.evidence = (best[key].evidence + "\n" + f.evidence).strip() if best[key].evidence else f.evidence
            best[key] = f
        else:
            existing = best[key]
            if f.tool != existing.tool and f.tool not in existing.evidence:
                existing.evidence = (existing.evidence + f"\nAlso reported by {f.tool}:{f.tool_rule}").strip()
    return sorted(best.values(), key=lambda x: (x.severity, x.rule_id, x.file, x.line))
