"""sklab-contract CLI — portable contract engineering across toolchains."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from sklab_contract_toolkit.version import __version__

app = typer.Typer(
    name="sklab-contract", add_completion=False, help="Build, inspect, test, analyze, and verify smart contracts."
)
console = Console()
err_console = Console(stderr=True)

_FORBIDDEN_KEY_PATTERNS = ("PRIVATE_KEY", "MNEMONIC", "SECRET", "SEED_PHRASE")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"sklab-contract {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    return None


def _resolve_target(path: str) -> Path:
    from sklab_contract_toolkit.core.pathsafety import PathSafetyError, resolve_root

    try:
        return resolve_root(path)
    except PathSafetyError as exc:
        err_console.print(f"[red]Path safety error: {exc}[/red]")
        raise typer.Exit(code=2) from exc


def _emit(data: Any, as_json: bool) -> None:
    if as_json:
        typer.echo(json.dumps(data, indent=2, default=str))
    else:
        typer.echo(json.dumps(data, indent=2, default=str))


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------


def build_inspection(root: Path | str, abi_path: str | None = None, bytecode_path: str | None = None) -> dict[str, Any]:
    """Shared inspection used by CLI, SDK, and Orchestrator integrations."""
    from sklab_contract_toolkit.analysis.authorities import extract_authorities
    from sklab_contract_toolkit.chains.registry import get_adapter
    from sklab_contract_toolkit.core.pathsafety import resolve_root
    from sklab_contract_toolkit.detection.project import detect_project
    from sklab_contract_toolkit.detection.solidity import (
        extract_abis,
        inventory_contracts,
        load_abi_file,
    )
    from sklab_contract_toolkit.graphs.builder import build_graphs
    from sklab_contract_toolkit.standards.categories import classify_contract
    from sklab_contract_toolkit.standards.registry import (
        detect_standards,
        detect_standards_from_abi,
    )

    root_path = resolve_root(root)
    detection = detect_project(root_path)
    adapter = get_adapter("evm" if detection.chain == "evm" else detection.chain)

    contracts: list[dict[str, Any]] = []
    standards: list[dict[str, Any]] = []
    source_available = True

    if abi_path or bytecode_path:
        # ABI / bytecode-only mode: reduced capabilities, honest labeling
        source_available = False
        entries: list[dict[str, Any]] = []
        if abi_path:
            entries = load_abi_file(Path(abi_path)).get("abi", [])
        if bytecode_path:
            try:
                code = Path(bytecode_path).read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                code = ""
            entries.append({"type": "bytecode", "size": len(code)})
        for match in detect_standards_from_abi(entries if isinstance(entries, list) else []):
            standards.append(
                {
                    "standard": match.standard,
                    "confidence": match.confidence,
                    "evidence": match.evidence,
                    "contracts": ["SOURCE_UNAVAILABLE"],
                }
            )
        contracts = [
            {
                "contract_name": "SOURCE_UNAVAILABLE",
                "note": "Bytecode/ABI-only input; source-level facts unavailable.",
                "abi_entries": len(entries) if isinstance(entries, list) else 0,
            }
        ]
    else:
        models = inventory_contracts(root_path)
        for model in models:
            try:
                source_text = (root_path / model.source_file).read_text(encoding="utf-8", errors="replace")
            except OSError:
                source_text = ""
            stds = detect_standards(model, source_text)
            model.standards = [s.model_dump() for s in stds]
            if not model.category or model.category == "CUSTOM":
                model.category = classify_contract(model)
            contracts.append(model.model_dump())
            for s in stds:
                standards.append(
                    {
                        "standard": s.standard,
                        "confidence": s.confidence,
                        "evidence": s.evidence,
                        "contracts": [model.contract_name],
                    }
                )

    authorities = [a.model_dump() for a in extract_authorities(root_path)] if source_available else []
    graphs = build_graphs(root_path) if source_available else {}
    abis = extract_abis(root_path) if source_available else {}

    return {
        "project": detection.model_dump(),
        "chain": {
            "chain": detection.chain,
            "adapter_state": adapter.state.value,
            "capabilities": adapter.capabilities(),
        },
        "contracts": contracts,
        "standards": standards,
        "authorities": authorities,
        "graphs": graphs,
        "abis": abis,
        "source_available": source_available,
        "toolkit_version": __version__,
    }


@app.command()
def inspect(
    path: str = typer.Argument(".", help="Project path, contract file, or directory"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
    abi: str | None = typer.Option(None, "--abi", help="Inspect an ABI JSON file instead of source"),
    bytecode: str | None = typer.Option(None, "--bytecode", help="Inspect a bytecode file instead of source"),
) -> None:
    """Detect project, inventory contracts, standards, and authorities."""
    root = _resolve_target(path)
    bundle = build_inspection(root, abi_path=abi, bytecode_path=bytecode)
    if json_output or abi or bytecode:
        typer.echo(json.dumps(bundle, indent=2, default=str))
        return
    _print_inspection(bundle)


def _print_inspection(bundle: dict[str, Any]) -> None:
    proj = bundle.get("project", {})
    console.print(f"[bold]Project:[/bold] {proj.get('kind')} (confidence {proj.get('confidence')})")
    console.print(
        f"[bold]Chain:[/bold] {bundle.get('chain', {}).get('chain')} [{bundle.get('chain', {}).get('adapter_state')}]"
    )
    if not bundle.get("source_available"):
        console.print("[yellow]SOURCE_UNAVAILABLE: bytecode/ABI-only input; reduced capabilities.[/yellow]")
    table = Table(title="Contracts")
    table.add_column("Contract")
    table.add_column("Source")
    table.add_column("Category")
    table.add_column("Functions")
    for c in bundle.get("contracts", []):
        if c.get("contract_name") == "SOURCE_UNAVAILABLE":
            table.add_row("SOURCE_UNAVAILABLE", "-", "-", "-")
            continue
        table.add_row(
            str(c.get("contract_name")),
            str(c.get("source_file")),
            str(c.get("category")),
            str(len(c.get("functions", []))),
        )
    console.print(table)
    if bundle.get("standards"):
        stable = Table(title="Standards detected")
        stable.add_column("Standard")
        stable.add_column("Confidence")
        stable.add_column("Contracts")
        for s in bundle["standards"]:
            stable.add_row(str(s.get("standard")), str(s.get("confidence")), ",".join(s.get("contracts", [])))
        console.print(stable)
    if bundle.get("authorities"):
        atable = Table(title="Authorities")
        atable.add_column("Authority")
        atable.add_column("Capability")
        atable.add_column("Target")
        for a in bundle["authorities"][:20]:
            atable.add_row(str(a.get("authority")), str(a.get("capability"))[:60], str(a.get("target_contract")))
        console.print(atable)


@app.command(name="inspect-address")
def inspect_address(
    chain: str = typer.Argument(..., help="Chain id, e.g. ethereum"),
    address: str = typer.Argument(..., help="Contract address (0x...)"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
) -> None:
    """Read-only inspection of a deployed address. No transactions, no keys."""
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
        err_console.print("[red]Invalid address (expected 0x + 40 hex chars).[/red]")
        raise typer.Exit(code=2)
    from sklab_contract_toolkit.core.config import load_config

    config = load_config()
    if not config.network.allow_readonly_rpc:
        err_console.print(
            "[yellow]Read-only RPC is disabled (network.allow_readonly_rpc=false). "
            "Enable it explicitly to use inspect-address.[/yellow]"
        )
    chains = config.chains or {"ethereum": {"rpc_url_env": "ETH_RPC_URL"}}
    rpc_env = (chains.get(chain) or {}).get("rpc_url_env", f"{chain.upper()}_RPC_URL")
    import os

    configured = bool(os.environ.get(rpc_env))
    bundle = {
        "chain": chain,
        "address": address,
        "rpc": {"env_var": rpc_env, "configured": configured},
        "capabilities": ["code", "abi-if-verified", "implementation-slot", "proxy-detection", "metadata"],
        "transactions": "disabled — read-only inspection only",
        "notes": "Configure a public RPC endpoint via environment; no private keys are ever used.",
    }
    typer.echo(json.dumps(bundle, indent=2))


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@app.command()
def tools(json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output")) -> None:
    """Show toolchain status: installed, version, capabilities. Never fake readiness."""
    from sklab_contract_toolkit.tools.manager import tools_json

    data = tools_json()
    if json_output:
        typer.echo(json.dumps(data, indent=2))
        return
    table = Table(title="Toolchains")
    table.add_column("Tool")
    table.add_column("Installed")
    table.add_column("Version")
    table.add_column("Status")
    table.add_column("Capabilities")
    for t in data:
        table.add_row(t["tool"], str(t["installed"]), str(t["version"])[:40], t["status"], ",".join(t["capabilities"]))
    console.print(table)


# ---------------------------------------------------------------------------
# Compile / test / fuzz / invariants / gas / coverage
# ---------------------------------------------------------------------------


@app.command()
def compile(
    path: str = typer.Argument(".", help="Project path"),
    timeout: int = typer.Option(600, "--timeout", help="Tool timeout in seconds"),
) -> None:
    """Compile with the detected toolchain. No deployment."""
    from sklab_contract_toolkit.testing.flows import compile_project

    result = compile_project(_resolve_target(path), timeout=timeout)
    typer.echo(json.dumps(result, indent=2, default=str))


@app.command()
def test(
    path: str = typer.Argument(".", help="Project path"),
    timeout: int = typer.Option(600, "--timeout", help="Tool timeout in seconds"),
) -> None:
    """Run Foundry/Hardhat tests with normalized output."""
    from sklab_contract_toolkit.testing.flows import run_tests

    typer.echo(json.dumps(run_tests(_resolve_target(path), timeout=timeout).model_dump(), indent=2))


@app.command()
def fuzz(
    path: str = typer.Argument(".", help="Project path"),
    runs: int = typer.Option(256, "--runs", help="Fuzz runs"),
    seed: str = typer.Option("0", "--seed", help="Fuzz seed for reproducibility"),
    timeout: int = typer.Option(600, "--timeout", help="Tool timeout in seconds"),
) -> None:
    """Run fuzz tests with recorded seed/runs."""
    from sklab_contract_toolkit.testing.flows import run_fuzz

    results = run_fuzz(_resolve_target(path), runs=runs, seed=seed, timeout=timeout)
    typer.echo(json.dumps([r.model_dump() for r in results], indent=2))


@app.command()
def invariants(
    path: str = typer.Argument(".", help="Project path"),
    timeout: int = typer.Option(600, "--timeout", help="Tool timeout in seconds"),
) -> None:
    """Check explicit/user-provided/public-standard invariants."""
    from sklab_contract_toolkit.testing.flows import run_invariants

    results = run_invariants(_resolve_target(path), timeout=timeout)
    typer.echo(json.dumps([r.model_dump() for r in results], indent=2))


@app.command()
def gas(
    path: str = typer.Argument(".", help="Project path"),
    timeout: int = typer.Option(600, "--timeout", help="Tool timeout in seconds"),
) -> None:
    """Gas review: hotspots and regressions."""
    from sklab_contract_toolkit.testing.flows import run_gas

    typer.echo(json.dumps(run_gas(_resolve_target(path), timeout=timeout).model_dump(), indent=2))


@app.command()
def coverage(
    path: str = typer.Argument(".", help="Project path"),
    timeout: int = typer.Option(600, "--timeout", help="Tool timeout in seconds"),
) -> None:
    """Coverage report (line/branch/function/statement). Not a security proof."""
    from sklab_contract_toolkit.testing.flows import run_coverage

    typer.echo(json.dumps(run_coverage(_resolve_target(path), timeout=timeout).model_dump(), indent=2))


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


@app.command()
def analyze(
    path: str = typer.Argument(".", help="Project path"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
    local_only: bool = typer.Option(False, "--local-only", help="No cloud AI; local tools only"),
    offline: bool = typer.Option(False, "--offline", help="No network; local toolchain only"),
    timeout: int = typer.Option(300, "--timeout", help="Per-tool timeout in seconds"),
) -> None:
    """Run internal checks + Slither (if available); normalize findings."""
    from sklab_contract_toolkit.analysis.engine import run_internal_analysis
    from sklab_contract_toolkit.analysis.slither_norm import run_slither
    from sklab_contract_toolkit.models.findings import deduplicate_findings

    root = _resolve_target(path)
    findings = run_internal_analysis(root)
    slither_meta: dict[str, Any] = {"available": False}
    if not offline:
        slither_meta = run_slither(root, timeout=timeout)
        findings.extend(slither_meta.get("findings", []))
    else:
        slither_meta = {"available": False, "notes": "offline: slither skipped"}
    findings = deduplicate_findings(findings)
    bundle = {
        "findings": [f.model_dump() for f in findings],
        "slither": {k: v for k, v in slither_meta.items() if k != "findings"},
        "local_only": local_only,
        "offline": offline,
    }
    if json_output or True:
        typer.echo(json.dumps(bundle, indent=2, default=str))


@app.command()
def graph(
    path: str = typer.Argument(".", help="Project path"),
    format: str = typer.Option("json", "--format", help="json|dot|mermaid"),
) -> None:
    """Export structural graphs (inheritance/import/call/dependency/external/authority)."""
    from sklab_contract_toolkit.graphs.builder import build_graphs, to_dot, to_mermaid

    graphs = build_graphs(_resolve_target(path))
    fmt = format.lower()
    if fmt == "json":
        typer.echo(json.dumps(graphs, indent=2, default=str))
    elif fmt == "dot":
        for name, g in graphs.items():
            typer.echo(f"# --- {name} ---")
            typer.echo(to_dot(name, g))
    elif fmt == "mermaid":
        for name, g in graphs.items():
            typer.echo(f"%% --- {name} ---")
            typer.echo(to_mermaid(name, g))
    else:
        err_console.print(f"[red]Unknown format: {format} (json|dot|mermaid)[/red]")
        raise typer.Exit(code=2)


# ---------------------------------------------------------------------------
# Upgrade / storage / ABI
# ---------------------------------------------------------------------------


@app.command(name="upgrade-review")
def upgrade_review(
    old: str = typer.Argument(..., help="Old project/version path"),
    new: str = typer.Argument(..., help="New project/version path"),
) -> None:
    """Review upgrade pair: SAFE / RISKY / INCOMPATIBLE / INCONCLUSIVE with evidence."""
    from sklab_contract_toolkit.upgrades.review import review_upgrade

    typer.echo(json.dumps(review_upgrade(_resolve_target(old), _resolve_target(new)).model_dump(), indent=2))


@app.command()
def storage(
    path: str = typer.Argument(".", help="Project path"),
) -> None:
    """Extract normalized storage layouts."""
    from sklab_contract_toolkit.upgrades.storage import extract_storage_layouts

    layouts = extract_storage_layouts(_resolve_target(path))
    typer.echo(json.dumps({k: v.model_dump() for k, v in layouts.items()}, indent=2))


@app.command(name="storage-diff")
def storage_diff(
    old: str = typer.Argument(..., help="Old project/version path"),
    new: str = typer.Argument(..., help="New project/version path"),
    contract: str | None = typer.Option(None, "--contract", help="Limit to one contract"),
) -> None:
    """Deterministically diff storage layouts."""
    from sklab_contract_toolkit.upgrades.storage import diff_storage, extract_storage_layouts

    old_layouts = extract_storage_layouts(_resolve_target(old))
    new_layouts = extract_storage_layouts(_resolve_target(new))
    names = [contract] if contract else sorted(set(old_layouts) | set(new_layouts))
    out: dict[str, Any] = {}
    for name in names:
        if name in old_layouts and name in new_layouts:
            out[name] = diff_storage(old_layouts[name], new_layouts[name])
        else:
            out[name] = {"error": "contract not present in both versions"}
    typer.echo(json.dumps(out, indent=2))


@app.command(name="abi-diff")
def abi_diff(
    old: str = typer.Argument(..., help="Old ABI JSON / Solidity file / project dir"),
    new: str = typer.Argument(..., help="New ABI JSON / Solidity file / project dir"),
) -> None:
    """Diff ABIs: functions, selectors, events, errors, mutability."""
    from sklab_contract_toolkit.upgrades.abi_diff import diff_abis, load_entries

    def _entries(ref: str) -> list[dict[str, Any]]:
        p = Path(ref)
        if p.is_dir():
            from sklab_contract_toolkit.detection.solidity import extract_abis

            entries: list[dict[str, Any]] = []
            for info in extract_abis(p).values():
                entries.extend(info.get("abi", []))
            return entries
        return load_entries(p)

    typer.echo(json.dumps(diff_abis(_entries(old), _entries(new)).model_dump(), indent=2))


# ---------------------------------------------------------------------------
# Fork / scaffolding / tokenomics / threat model
# ---------------------------------------------------------------------------


@app.command()
def fork(
    action: str = typer.Argument(..., help="create"),
    chain: str = typer.Option("ethereum", "--chain", help="Chain id"),
    block: int | None = typer.Option(None, "--block", help="Fork block number"),
) -> None:
    """Local EVM fork preparation through Anvil (127.0.0.1, no broadcast)."""
    if action != "create":
        err_console.print(f"[red]Unknown fork action: {action} (only 'create')[/red]")
        raise typer.Exit(code=2)
    from sklab_contract_toolkit.tools.fork import create_fork_config

    typer.echo(json.dumps(create_fork_config(chain=chain, block=block), indent=2))


@app.command(name="new")
def new_project(
    kind: str = typer.Argument(..., help="token|nft|vault|staking|custom"),
    dest: str = typer.Argument(..., help="Destination directory"),
) -> None:
    """Scaffold a new contract project from SKLab templates."""
    from sklab_contract_toolkit.tools.scaffold import scaffold

    try:
        result = scaffold(kind, dest)
    except ValueError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(result, indent=2))


@app.command(name="token-check")
def token_check(path: str = typer.Argument(".", help="Project path")) -> None:
    """Deterministic tokenomics/config arithmetic review."""
    from sklab_contract_toolkit.testing.tokenomics import review_token_config

    typer.echo(json.dumps(review_token_config(_resolve_target(path)), indent=2, default=str))


@app.command(name="threat-model")
def threat_model(path: str = typer.Argument(".", help="Project path")) -> None:
    """Populate the public threat-model template with deterministic facts."""
    from sklab_contract_toolkit.analysis.threat_model import build_threat_model

    typer.echo(json.dumps(build_threat_model(_resolve_target(path)), indent=2, default=str))


# ---------------------------------------------------------------------------
# Remediation / verification / reports / misc
# ---------------------------------------------------------------------------


@app.command()
def fix(
    ref: str = typer.Argument(..., help="Finding ID or rule ID"),
    path: str = typer.Argument(".", help="Project path"),
    out: str | None = typer.Option(None, "--out", help="Isolated output directory for patch"),
) -> None:
    """Generate a remediation patch in an isolated workspace (default: return patch)."""
    from sklab_contract_toolkit.analysis.remediation import prepare_fix

    result = prepare_fix(ref, _resolve_target(path), out_dir=Path(out) if out else None)
    typer.echo(json.dumps(result, indent=2, default=str))


@app.command()
def verify(
    ref: str = typer.Argument(..., help="Finding ID or rule ID"),
    path: str = typer.Argument(".", help="Project path"),
) -> None:
    """Re-run compile/tests/analysis to verify a remediation."""
    from sklab_contract_toolkit.analysis.remediation import verify_fix

    typer.echo(json.dumps(verify_fix(ref, _resolve_target(path)).model_dump(), indent=2))


@app.command()
def report(
    path: str = typer.Argument(".", help="Project path"),
    out: str = typer.Option("contract-report", "--out", help="Output directory"),
    analyze_first: bool = typer.Option(True, "--analyze/--no-analyze", help="Run analysis"),
) -> None:
    """Generate contract-report.md / .json / .sarif."""
    from sklab_contract_toolkit.reports.builder import build_report_bundle, write_reports

    root = _resolve_target(path)
    inspection = build_inspection(root)
    findings: list[dict[str, Any]] = []
    if analyze_first:
        from sklab_contract_toolkit.analysis.engine import run_internal_analysis
        from sklab_contract_toolkit.analysis.slither_norm import run_slither
        from sklab_contract_toolkit.models.findings import deduplicate_findings

        found = run_internal_analysis(root)
        slither = run_slither(root)
        found.extend(slither.get("findings", []))
        findings = [f.model_dump() for f in deduplicate_findings(found)]
    from sklab_contract_toolkit.testing.flows import run_tests

    tests = run_tests(root).model_dump()
    bundle = build_report_bundle(
        root,
        contracts=inspection["contracts"],
        standards=inspection["standards"],
        authorities=inspection["authorities"],
        findings=findings,
        tests=tests,
        project=inspection["project"],
    )
    paths = write_reports(bundle, Path(out))
    typer.echo(json.dumps({"reports": paths, "scan_fingerprint": bundle["scan_fingerprint"]}, indent=2))


@app.command()
def rules() -> None:
    """List versioned internal static rules."""
    from sklab_contract_toolkit.analysis.engine import list_rules

    typer.echo(json.dumps(list_rules(), indent=2))


@app.command()
def skills() -> None:
    """Validate and list the public Contract Skill Pack."""
    from sklab_contract_toolkit.skills.pack import validate_pack

    typer.echo(json.dumps(validate_pack(), indent=2))


@app.command()
def chains() -> None:
    """List chain adapters and honest support states."""
    from sklab_contract_toolkit.chains.registry import list_adapters

    typer.echo(json.dumps(list_adapters(), indent=2))


def _check_secret_leak(text: str) -> list[str]:
    hits = []
    for pattern in _FORBIDDEN_KEY_PATTERNS:
        if pattern in text.upper():
            hits.append(pattern)
    return hits


if __name__ == "__main__":
    app()
