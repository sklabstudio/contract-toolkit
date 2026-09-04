"""Path safety: confine all toolkit file operations to the project root.

Rejects path traversal, symlink escapes, accidental `/` scans, and writes
outside the target project root.
"""

from __future__ import annotations

from pathlib import Path


class PathSafetyError(ValueError):
    pass


def resolve_root(path: Path | str) -> Path:
    root = Path(path).resolve()
    if not root.exists():
        raise PathSafetyError(f"Project path does not exist: {path}")
    if root.is_file():
        root = root.parent
    return root.resolve()


def ensure_inside_root(root: Path, candidate: Path | str) -> Path:
    """Resolve `candidate` and ensure it stays inside `root` (symlinks resolved)."""
    root_resolved = root.resolve()
    text = str(candidate)
    if text.strip() in ("", "/", "\\"):
        raise PathSafetyError("Refusing to operate on filesystem root")
    cand_path = Path(candidate)
    if not cand_path.is_absolute():
        cand_path = root_resolved / cand_path
    resolved = cand_path.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError:
        raise PathSafetyError(f"Path escapes project root: {candidate}") from None
    return resolved


def safe_read_text(root: Path, candidate: Path | str, max_bytes: int = 5_000_000) -> str:
    resolved = ensure_inside_root(root, candidate)
    if resolved.is_symlink():
        # resolve already followed the link; re-check containment
        ensure_inside_root(root, resolved)
    if not resolved.is_file():
        raise PathSafetyError(f"Not a file: {candidate}")
    if resolved.stat().st_size > max_bytes:
        raise PathSafetyError(f"File too large to read safely: {candidate}")
    return resolved.read_text(encoding="utf-8", errors="replace")


def safe_write_text(root: Path, candidate: Path | str, content: str) -> Path:
    resolved = ensure_inside_root(root, candidate)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(content, encoding="utf-8")
    return resolved


def iter_project_files(root: Path, suffixes: tuple[str, ...] = (".sol",)) -> list[Path]:
    """List project files with given suffixes, skipping VCS/dependency dirs."""
    root = root.resolve()
    skip = {".git", "node_modules", "artifacts", "cache", "out", ".venv", "venv", "lib", "coverage"}
    results: list[Path] = []
    for path in sorted(root.rglob("*")):
        if any(part in skip for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in suffixes:
            try:
                path.relative_to(root)
            except ValueError:
                continue
            results.append(path)
    return results
