# Chain Adapters

Interface: `src/sklab_contract_toolkit/chains/base.py` (`ChainAdapter`).

Adapter states: `SUPPORTED | PARTIAL | EXPERIMENTAL | UNAVAILABLE`.
Never fake support — `capabilities()` must reflect reality.

| Chain      | State (v0.1.0) | Notes                          |
|------------|----------------|--------------------------------|
| EVM        | SUPPORTED      | Full: detect/compile/test/fuzz |
| Solana     | EXPERIMENTAL   | Stub; Anchor planned           |
| Move/Aptos | EXPERIMENTAL   | Stub                           |
| Move/Sui   | EXPERIMENTAL   | Stub                           |
| CosmWasm   | EXPERIMENTAL   | Stub                           |
| TON        | UNAVAILABLE    | Stub                           |

Each adapter exposes: `detect_project`, `detect_sources`, `detect_artifacts`,
`detect_contracts`, `compile`, `test`, `analyze`, `extract_abi`,
`extract_storage`, `extract_authorities`, `extract_upgradeability`,
`normalize_findings`, `capabilities`, `tool_requirements`.

Extend without touching core:

```python
from sklab_contract_toolkit.chains.registry import register_adapter
register_adapter("my-chain", MyAdapter())
```
