"""Weighted project detection: Foundry / Hardhat / raw / mixed / Truffle legacy."""

from __future__ import annotations

from pathlib import Path

from sklab_contract_toolkit.models.project import DetectionEvidence, ProjectDetection


def _exists(root: Path, name: str) -> bool:
    return (root / name).exists()


def _glob_exists(root: Path, pattern: str) -> bool:
    return any(root.glob(pattern))


def detect_project(root: Path | str) -> ProjectDetection:
    root_path = Path(root).resolve()
    scores: dict[str, float] = {
        "foundry": 0.0,
        "hardhat": 0.0,
        "raw_solidity": 0.0,
        "mixed_solidity": 0.0,
        "truffle_legacy": 0.0,
    }
    evidence: dict[str, list[DetectionEvidence]] = {k: [] for k in scores}

    def add(kind: str, signal: str, weight: float, detail: str = "") -> None:
        scores[kind] += weight
        evidence[kind].append(DetectionEvidence(signal=signal, weight=weight, detail=detail))

    if _exists(root_path, "foundry.toml"):
        add("foundry", "foundry.toml", 5.0, "Foundry project manifest")
    if _exists(root_path, "remappings.txt"):
        add("foundry", "remappings.txt", 1.5)
        add("mixed_solidity", "remappings.txt", 0.5)
    if (root_path / "src").is_dir() and _glob_exists(root_path, "src/*.sol"):
        add("foundry", "src/*.sol layout", 2.0)
    if (root_path / "script").is_dir():
        add("foundry", "script/ directory", 1.0)
    if _glob_exists(root_path, "test/*.sol") or _glob_exists(root_path, "test/**/*.sol"):
        add("foundry", "Solidity tests", 1.5)
    if (root_path / "lib").is_dir():
        add("foundry", "lib/ dependencies", 1.0)

    if _glob_exists(root_path, "hardhat.config.*"):
        add("hardhat", "hardhat.config.*", 5.0, "Hardhat project config")
    if _exists(root_path, "package.json"):
        try:
            text = (root_path / "package.json").read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if "hardhat" in text:
            add("hardhat", "hardhat in package.json", 2.5)
        if "ethers" in text or "viem" in text or "web3" in text:
            add("hardhat", "EVM JS client dependency", 0.5)
    if (root_path / "contracts").is_dir() and _glob_exists(root_path, "contracts/*.sol"):
        add("hardhat", "contracts/*.sol layout", 2.0)
    if (root_path / "test").is_dir() and (_glob_exists(root_path, "test/*.js") or _glob_exists(root_path, "test/*.ts")):
        add("hardhat", "JS/TS tests", 1.5)
    if (root_path / "scripts").is_dir():
        add("hardhat", "scripts/ directory", 0.5)

    sol_files = [p for p in root_path.rglob("*.sol") if ".git" not in p.parts and "node_modules" not in p.parts]
    if sol_files and not _exists(root_path, "foundry.toml") and not _glob_exists(root_path, "hardhat.config.*"):
        add("raw_solidity", f"{len(sol_files)} bare .sol files", 3.0)
    if sol_files:
        add("raw_solidity", f"{len(sol_files)} .sol files present", 0.5)

    if _exists(root_path, "foundry.toml") and _glob_exists(root_path, "hardhat.config.*"):
        add("mixed_solidity", "foundry.toml + hardhat.config.*", 4.0)
    if (root_path / "contracts").is_dir() and (root_path / "src").is_dir():
        add("mixed_solidity", "contracts/ + src/ layouts", 2.0)

    if _exists(root_path, "truffle-config.js") or _glob_exists(root_path, "truffle-config.*"):
        add("truffle_legacy", "truffle config", 5.0)
    if _exists(root_path, "migrations"):
        add("truffle_legacy", "migrations/ directory", 1.5)

    if _exists(root_path, "artifacts"):
        add("hardhat", "artifacts/ directory", 0.5)
    if _exists(root_path, "out"):
        add("foundry", "out/ directory", 0.5)

    kind = max(scores, key=lambda k: scores[k])
    if scores[kind] <= 0:
        kind = "unknown"
        confidence = 0.0
    else:
        total = sum(scores.values())
        confidence = round(scores[kind] / total if total > 0 else 0.0, 3)

    toolchain = {"foundry": "foundry", "hardhat": "hardhat"}.get(kind, "auto")
    if kind in ("raw_solidity", "mixed_solidity", "unknown"):
        toolchain = "auto"

    notes: list[str] = []
    if kind == "unknown":
        notes.append("No recognized Solidity project signals; treating as unknown.")
    return ProjectDetection(
        kind=kind,
        chain="evm",
        confidence=confidence,
        evidence=evidence.get(kind, []),
        root=str(root_path),
        toolchain=toolchain,
        notes=notes,
    )
