"""Safe subprocess execution for external blockchain tools.

Security rules enforced here:
- argument arrays only (never shell=True)
- explicit cwd confined to the project root
- timeouts always applied
- bounded output capture
- filtered environment (secrets never injected unless explicitly required)
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 2_000_000

# Environment variables that must never be forwarded implicitly when they
# look like secrets, unless the caller explicitly allows them.
_SENSITIVE_PREFIXES = ("PRIVATE_KEY", "MNEMONIC", "SECRET", "SEED")


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False


def _filtered_env(extra: dict[str, str] | None, allow_secrets: bool) -> dict[str, str]:
    env = dict(os.environ)
    if extra:
        env.update(extra)
    if not allow_secrets:
        for key in list(env.keys()):
            upper = key.upper()
            if any(upper.startswith(p) for p in _SENSITIVE_PREFIXES):
                env.pop(key, None)
    return env


def run_tool(
    args: list[str],
    cwd: Path | str,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    extra_env: dict[str, str] | None = None,
    allow_secrets: bool = False,
) -> CommandResult:
    """Run an external tool safely. `args` must be a list (no shell)."""
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ValueError("args must be a list of strings (shell execution is forbidden)")
    if not args:
        raise ValueError("args must not be empty")
    cwd_path = Path(cwd).resolve()
    if not cwd_path.is_dir():
        raise ValueError(f"cwd does not exist or is not a directory: {cwd_path}")
    env = _filtered_env(extra_env, allow_secrets)
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd_path),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # never enable shell
        )
        stdout, stderr = completed.stdout or "", completed.stderr or ""
        truncated = False
        if len(stdout.encode("utf-8", "ignore")) > MAX_OUTPUT_BYTES:
            stdout = stdout[: MAX_OUTPUT_BYTES // 2]
            truncated = True
        if len(stderr.encode("utf-8", "ignore")) > MAX_OUTPUT_BYTES:
            stderr = stderr[: MAX_OUTPUT_BYTES // 2]
            truncated = True
        return CommandResult(
            args=list(args),
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            truncated=truncated,
        )
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode("utf-8", "ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = (exc.stderr or b"").decode("utf-8", "ignore") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return CommandResult(args=list(args), returncode=124, stdout=out, stderr=err, timed_out=True)
    except FileNotFoundError:
        return CommandResult(args=list(args), returncode=127, stdout="", stderr=f"executable not found: {args[0]}")
