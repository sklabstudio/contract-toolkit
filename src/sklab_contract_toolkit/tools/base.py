"""Tool adapter base class + ToolInfo record."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from sklab_contract_toolkit.core.subprocess import run_tool


@dataclass
class ToolInfo:
    tool: str
    installed: bool = False
    version: str = ""
    status: str = "unavailable"  # ready | unavailable | error
    capabilities: list[str] = field(default_factory=list)
    path: str = ""
    notes: str = ""


class ToolAdapter(ABC):
    name: str = "unknown"
    capabilities: list[str] = []

    def detect(self) -> ToolInfo:
        exe = shutil.which(self.name)
        if not exe:
            # check common aliases
            for alias in self.aliases():
                exe = shutil.which(alias)
                if exe:
                    break
        if not exe:
            return ToolInfo(
                tool=self.name,
                installed=False,
                status="unavailable",
                capabilities=self.capabilities,
                notes=f"{self.name} not found on PATH",
            )
        version = self.version(exe)
        return ToolInfo(
            tool=self.name,
            installed=True,
            version=version,
            status="ready" if version else "ready",
            capabilities=self.capabilities,
            path=exe,
        )

    def aliases(self) -> list[str]:
        return []

    def version(self, exe: str) -> str:
        try:
            result = run_tool([exe, "--version"], cwd=Path.cwd(), timeout=30)
            out = (result.stdout + " " + result.stderr).strip().splitlines()
            return out[0].strip()[:120] if out else ""
        except Exception:
            return ""

    @abstractmethod
    def fingerprint(self) -> str: ...
