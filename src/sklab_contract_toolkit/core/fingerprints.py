"""Stable SHA-256 fingerprints for scans, builds, and findings.

Fingerprints must be deterministic: no timestamps, no absolute paths,
no environment-specific noise. Inputs are normalized (sorted keys,
POSIX relative paths) before hashing.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def fingerprint_mapping(mapping: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(mapping))


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def source_tree_fingerprint(root: Path, patterns: Iterable[str] = ("*.sol",)) -> str:
    """Hash all matching source files by relative POSIX path + content."""
    root = root.resolve()
    entries: list[dict[str, str]] = []
    for pattern in patterns:
        for path in sorted(root.rglob(pattern)):
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                continue
            if ".git" in path.parts or "node_modules" in path.parts:
                continue
            try:
                entries.append({"path": rel, "sha256": file_sha256(path)})
            except OSError:
                continue
    entries.sort(key=lambda e: e["path"])
    return fingerprint_mapping({"files": entries})


def scan_fingerprint(
    source_fingerprint: str,
    compiler: str,
    compiler_version: str,
    tool_versions: dict[str, str],
    config_digest: str,
    ruleset_version: str,
) -> str:
    return fingerprint_mapping(
        {
            "kind": "sklab-contract-scan",
            "version": 1,
            "source": source_fingerprint,
            "compiler": compiler,
            "compiler_version": compiler_version,
            "tools": dict(sorted(tool_versions.items())),
            "config": config_digest,
            "ruleset": ruleset_version,
        }
    )


def finding_fingerprint(
    rule_id: str,
    rule_version: str,
    contract: str,
    function: str,
    file: str,
    line: int,
    title: str,
) -> str:
    return fingerprint_mapping(
        {
            "kind": "sklab-contract-finding",
            "version": 1,
            "rule_id": rule_id,
            "rule_version": rule_version,
            "contract": contract,
            "function": function,
            "file": file,
            "line": line,
            "title": title,
        }
    )
