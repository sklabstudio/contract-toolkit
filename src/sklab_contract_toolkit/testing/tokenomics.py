"""Public deterministic tokenomics / config arithmetic review helpers.

Validates caps, fee bounds, decimals, reward rates, vesting schedules,
allocation totals, basis-point sums — with documented assumptions.
Does NOT claim full economic security.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sklab_contract_toolkit.core.pathsafety import resolve_root
from sklab_contract_toolkit.detection.solidity import inventory_contracts

MAX_BPS = 10_000


def review_token_config(root: Path | str) -> dict[str, Any]:
    root_path = resolve_root(root)
    findings: list[dict[str, Any]] = []
    facts: dict[str, Any] = {}
    for model in inventory_contracts(root_path):
        try:
            source = (root_path / model.source_file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # decimals
        m = re.search(r"decimals\s*\(\)[^{]*\{[^}]*return\s+(\d+)", source)
        if m:
            facts[f"{model.contract_name}.decimals"] = int(m.group(1))
            if int(m.group(1)) > 36:
                findings.append(
                    {
                        "check": "decimals",
                        "contract": model.contract_name,
                        "status": "WARN",
                        "detail": f"decimals={m.group(1)} unusually high",
                    }
                )
        m2 = re.search(r"uint8\s+(?:public\s+|private\s+|internal\s+)?decimals\s*=\s*(\d+)", source)
        if m2:
            facts[f"{model.contract_name}.decimals"] = int(m2.group(1))
        # max supply / cap
        for pat in (
            r"(?:MAX_SUPPLY|MAXSUPPLY|CAP|cap|_cap)\s*=\s*([\d_]+(?:\s*\*\*?\s*[\d_]+)?)",
            r"require\s*\(\s*totalSupply\s*\(\s*\)\s*\+\s*amount\s*<=\s*([\d_\w]+)",
        ):
            for mm in re.finditer(pat, source):
                facts.setdefault(f"{model.contract_name}.supply_cap_expr", mm.group(1).strip())
        # fee bounds in basis points
        for mm in re.finditer(r"(\w*[Ff]ee\w*)\s*=\s*(\d+)", source):
            name, value = mm.group(1), int(mm.group(2))
            facts[f"{model.contract_name}.{name}"] = value
            if value > MAX_BPS:
                findings.append(
                    {
                        "check": "fee-bounds",
                        "contract": model.contract_name,
                        "status": "WARN",
                        "detail": f"{name}={value} exceeds 10000 bps convention; verify unit",
                    }
                )
        # basis-point sums: feeA + feeB <= 10000 patterns
        for mm in re.finditer(r"require\s*\(([^;]{0,200}<=?\s*10000[^;]{0,50})\)", source):
            facts.setdefault(f"{model.contract_name}.bps_guard", mm.group(1).strip()[:160])
        # reward rates
        for mm in re.finditer(r"(reward[Rr]ate|rewardPerSecond|emissionRate)\s*=\s*([\d_]+)", source):
            facts[f"{model.contract_name}.{mm.group(1)}"] = mm.group(2)
        # vesting schedules
        for mm in re.finditer(r"(duration|cliff|vesting\w*)\s*[:=]\s*([\d_]+)", source, re.IGNORECASE):
            facts.setdefault(f"{model.contract_name}.vesting_{mm.group(1)}", mm.group(2))
        # allocation totals: look for arrays of allocations
        for mm in re.finditer(r"allocations?\s*=\s*\[([^\]]+)\]", source, re.IGNORECASE):
            nums = [int(n) for n in re.findall(r"\d+", mm.group(1))]
            if nums:
                total = sum(nums)
                facts[f"{model.contract_name}.allocation_total"] = total
                if total != 100 and total != 10000 and total > 10000:
                    findings.append(
                        {
                            "check": "allocation-total",
                            "contract": model.contract_name,
                            "status": "WARN",
                            "detail": f"allocation total={total}; verify expected unit (100 vs 10000 bps)",
                        }
                    )
    status = "PASS" if not findings else "WARN"
    return {
        "status": status,
        "facts": facts,
        "findings": findings,
        "assumptions": "Heuristic source review only; verify units (wei vs BPS vs percent) manually.",
    }
