"""Fork support: local Anvil fork preparation (127.0.0.1 only, no broadcast)."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any

from sklab_contract_toolkit.core.config import load_config


def redact_rpc_url(url: str) -> str:
    """Redact secret-bearing parts of an RPC URL for safe logging."""
    if "://" in url and "@" in url:
        scheme, rest = url.split("://", 1)
        _, host = rest.rsplit("@", 1)
        return f"{scheme}://***@{host}"
    # redact long hex/api-key query params
    redacted = re.sub(r"([?&](?:api[_-]?key|key|token)=)[^&]+", r"\1***", url, flags=re.IGNORECASE)
    return redacted


def create_fork_config(
    chain: str = "ethereum", block: int | None = None, rpc_env: str | None = None, root: Path | str = "."
) -> dict[str, Any]:
    from sklab_contract_toolkit.tools.manager import list_tools

    config = load_config(start=Path(root).resolve())
    chains = config.chains or {"ethereum": {"rpc_url_env": "ETH_RPC_URL"}}
    chain_cfg = chains.get(chain, {"rpc_url_env": f"{chain.upper()}_RPC_URL"})
    env_var = rpc_env or chain_cfg.get("rpc_url_env", "ETH_RPC_URL")
    rpc_url = os.environ.get(env_var, "")
    anvil = next((t for t in list_tools() if t.tool == "anvil"), None)
    return {
        "chain": chain,
        "block_number": block,
        "rpc_source": {
            "env_var": env_var,
            "configured": bool(rpc_url),
            "redacted": redact_rpc_url(rpc_url) if rpc_url else "",
        },
        "anvil": {"installed": bool(anvil and anvil.installed), "version": (anvil.version if anvil else "")},
        "bind": "127.0.0.1",
        "broadcast": False,
        "command": _fork_command(rpc_url, block),
        "notes": "Local fork only. Never broadcast; Anvil binds 127.0.0.1 by default.",
    }


def _fork_command(rpc_url: str, block: int | None) -> list[str]:
    if not shutil.which("anvil"):
        return ["anvil", "--host", "127.0.0.1", "(install foundry to use local forks)"]
    cmd = ["anvil", "--host", "127.0.0.1"]
    if rpc_url:
        cmd += ["--fork-url", rpc_url]
    if block is not None:
        cmd += ["--fork-block-number", str(block)]
    return cmd
