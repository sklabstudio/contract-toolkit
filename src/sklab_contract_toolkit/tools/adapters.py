"""Concrete tool adapters: solc, forge, anvil, hardhat, slither, optional tools."""

from __future__ import annotations

from sklab_contract_toolkit.tools.base import ToolAdapter


class SolcAdapter(ToolAdapter):
    name = "solc"
    capabilities = ["compile", "storage-layout", "abi", "version-fingerprint"]

    def fingerprint(self) -> str:
        return f"solc:{self.detect().version}"


class ForgeAdapter(ToolAdapter):
    name = "forge"
    capabilities = ["compile", "test", "fuzz", "invariants", "gas", "coverage"]

    def aliases(self) -> list[str]:
        return ["foundry-forge"]

    def fingerprint(self) -> str:
        return f"forge:{self.detect().version}"


class AnvilAdapter(ToolAdapter):
    name = "anvil"
    capabilities = ["local-fork", "local-node", "simulate"]

    def fingerprint(self) -> str:
        return f"anvil:{self.detect().version}"


class HardhatAdapter(ToolAdapter):
    name = "hardhat"
    capabilities = ["compile", "test", "coverage", "gas"]

    def aliases(self) -> list[str]:
        return ["npx-hardhat"]

    def fingerprint(self) -> str:
        return f"hardhat:{self.detect().version}"


class SlitherAdapter(ToolAdapter):
    name = "slither"
    capabilities = ["static-analysis", "detectors", "json-output"]

    def fingerprint(self) -> str:
        return f"slither:{self.detect().version}"


class EchidnaAdapter(ToolAdapter):
    name = "echidna"
    capabilities = ["fuzz", "properties"]

    def fingerprint(self) -> str:
        return f"echidna:{self.detect().version}"


class MythrilAdapter(ToolAdapter):
    name = "myth"
    capabilities = ["symbolic-analysis"]

    def aliases(self) -> list[str]:
        return ["mythril"]

    def fingerprint(self) -> str:
        return f"mythril:{self.detect().version}"


class HalmosAdapter(ToolAdapter):
    name = "halmos"
    capabilities = ["symbolic-test", "formal-checks"]

    def fingerprint(self) -> str:
        return f"halmos:{self.detect().version}"


class AderynAdapter(ToolAdapter):
    name = "aderyn"
    capabilities = ["static-analysis", "rust-detectors"]

    def fingerprint(self) -> str:
        return f"aderyn:{self.detect().version}"


class SolhintAdapter(ToolAdapter):
    name = "solhint"
    capabilities = ["lint", "style-checks"]

    def fingerprint(self) -> str:
        return f"solhint:{self.detect().version}"


ALL_ADAPTERS: list[ToolAdapter] = [
    SolcAdapter(),
    ForgeAdapter(),
    AnvilAdapter(),
    HardhatAdapter(),
    SlitherAdapter(),
    EchidnaAdapter(),
    MythrilAdapter(),
    HalmosAdapter(),
    AderynAdapter(),
    SolhintAdapter(),
]
