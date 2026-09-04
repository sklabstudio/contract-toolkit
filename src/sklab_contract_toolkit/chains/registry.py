"""Chain adapter registry + plugin hook for proprietary adapters."""

from __future__ import annotations

from collections.abc import Callable

from sklab_contract_toolkit.chains.base import ChainAdapter
from sklab_contract_toolkit.chains.evm import EvmAdapter
from sklab_contract_toolkit.chains.future import (
    CosmWasmAdapter,
    MoveAptosAdapter,
    MoveSuiAdapter,
    SolanaAdapter,
    TonAdapter,
)

_REGISTRY: dict[str, ChainAdapter] = {
    "evm": EvmAdapter(),
    "solana": SolanaAdapter(),
    "move-aptos": MoveAptosAdapter(),
    "move-sui": MoveSuiAdapter(),
    "cosmwasm": CosmWasmAdapter(),
    "ton": TonAdapter(),
}

PluginFactory = Callable[[], ChainAdapter]


def register_adapter(chain_id: str, adapter: ChainAdapter) -> None:
    """Public extension hook: private repos can add adapters without touching core."""
    _REGISTRY[chain_id] = adapter


def get_adapter(chain_id: str) -> ChainAdapter:
    key = (chain_id or "auto").lower()
    if key == "auto":
        return _REGISTRY["evm"]
    return _REGISTRY.get(key, _REGISTRY["evm"])


def list_adapters() -> dict[str, str]:
    return {chain_id: adapter.state.value for chain_id, adapter in _REGISTRY.items()}
