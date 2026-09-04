# Toolchains

Manager: `src/sklab_contract_toolkit/tools/manager.py`.

- `sklab-contract tools [--json]` lists tool/installed/version/status/capabilities/path/notes.
- Priority: solc, Foundry/forge, Anvil, Hardhat, Slither.
- Optional (graceful when absent): Echidna, Mythril, Halmos, Aderyn, Solhint.
- `choose_toolchain()` combines weighted project detection with installed tools.
- Every external call goes through `core/subprocess.py`: argv arrays, explicit
  cwd, timeout, bounded output, filtered env, never `shell=True`.
- No automatic system-wide installation. A future `sklab-stack` may install tools.
