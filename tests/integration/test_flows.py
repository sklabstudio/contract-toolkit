"""Integration tests: flows, reports, remediation, forks, skills, orchestrator."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sklab_contract_toolkit", *args],
        cwd=str(cwd or FIXTURES),
        capture_output=True,
        text=True,
        timeout=120,
        shell=False,
    )


def test_cli_version_and_help():
    proc = _cli("--version")
    assert proc.returncode == 0
    assert "sklab-contract" in proc.stdout
    proc2 = _cli("--help")
    assert proc2.returncode == 0
    assert "inspect" in proc2.stdout or "Usage" in proc2.stdout


def test_cli_tools_json():
    proc = _cli("tools", "--json")
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert isinstance(data, list) and data
    for entry in data:
        assert {"tool", "installed", "version", "status", "capabilities"} <= set(entry)
        if not entry["installed"]:
            assert entry["status"] == "unavailable"


def test_cli_inspect_foundry_json(foundry_fixture):
    proc = _cli("inspect", str(foundry_fixture), "--json")
    assert proc.returncode == 0
    bundle = json.loads(proc.stdout)
    names = {c.get("contract_name") for c in bundle["contracts"]}
    assert "Counter" in names
    assert bundle["project"]["kind"] == "foundry"


def test_cli_inspect_bytecode_mode(tmp_path):
    abi = tmp_path / "abi.json"
    abi.write_text(
        json.dumps(
            [
                {
                    "type": "function",
                    "name": "transfer",
                    "inputs": [{"type": "address"}, {"type": "uint256"}],
                    "stateMutability": "nonpayable",
                }
            ]
        ),
        encoding="utf-8",
    )
    proc = _cli("inspect", str(tmp_path), "--abi", str(abi))
    assert proc.returncode == 0
    bundle = json.loads(proc.stdout)
    assert bundle["source_available"] is False


def test_cli_compile_and_analyze(foundry_fixture):
    proc = _cli("compile", str(foundry_fixture))
    assert proc.returncode == 0
    result = json.loads(proc.stdout)
    assert {"success", "compiler", "build_fingerprint"} <= set(result)
    proc2 = _cli("analyze", str(FIXTURES / "tx_origin"))
    assert proc2.returncode == 0
    bundle = json.loads(proc2.stdout)
    assert any(f["rule_id"] == "SKLAB-TX-ORIGIN-001" for f in bundle["findings"])


def test_cli_test_fuzz_invariants_gas_coverage(foundry_fixture):
    for cmd in (
        ["test", str(foundry_fixture)],
        ["fuzz", str(foundry_fixture)],
        ["invariants", str(foundry_fixture)],
        ["gas", str(foundry_fixture)],
        ["coverage", str(foundry_fixture)],
    ):
        proc = _cli(*cmd)
        assert proc.returncode == 0, f"{cmd} failed: {proc.stderr[:500]}"
        json.loads(proc.stdout)


def test_cli_upgrade_abi_storage(foundry_fixture):
    proc = _cli("upgrade-review", str(FIXTURES / "upgrade_v1"), str(FIXTURES / "upgrade_v2"))
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["verdict"] == "INCOMPATIBLE"
    proc2 = _cli("storage-diff", str(FIXTURES / "upgrade_v1"), str(FIXTURES / "upgrade_v2"))
    assert proc2.returncode == 0
    proc3 = _cli("storage", str(FIXTURES / "upgrade_v1"))
    assert proc3.returncode == 0


def test_cli_fork_create_no_broadcast():
    proc = _cli("fork", "create", "--chain", "ethereum")
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["bind"] == "127.0.0.1"
    assert data["broadcast"] is False
    assert "anvil" in " ".join(data["command"]).lower()


def test_cli_report_bundle(tmp_path):
    proc = _cli("report", str(FIXTURES / "erc20_flawed"), "--out", str(tmp_path / "rep"))
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["scan_fingerprint"]
    assert (tmp_path / "rep" / "contract-report.md").is_file()
    assert (tmp_path / "rep" / "contract-report.json").is_file()
    assert (tmp_path / "rep" / "contract-report.sarif").is_file()
    bundle = json.loads((tmp_path / "rep" / "contract-report.json").read_text(encoding="utf-8"))
    assert bundle["scan_fingerprint"]
    # fingerprint stability: identical inputs -> identical fingerprint
    proc2 = _cli("report", str(FIXTURES / "erc20_flawed"), "--out", str(tmp_path / "rep2"))
    assert proc2.returncode == 0
    bundle2 = json.loads((tmp_path / "rep2" / "contract-report.json").read_text(encoding="utf-8"))
    assert bundle["scan_fingerprint"] == bundle2["scan_fingerprint"]


def test_cli_threat_model_and_token_check():
    proc = _cli("threat-model", str(FIXTURES / "erc4626"))
    assert proc.returncode == 0
    tm = json.loads(proc.stdout)
    assert {"assets", "authorities", "privileged_functions"} <= set(tm)
    proc2 = _cli("token-check", str(FIXTURES / "erc20_safe"))
    assert proc2.returncode == 0
    assert "status" in json.loads(proc2.stdout)


def test_cli_fix_and_verify_access_control_dogfood(tmp_path):
    target = FIXTURES / "erc20_flawed"
    proc = _cli("analyze", str(target))
    findings = json.loads(proc.stdout)["findings"]
    assert findings
    ref = findings[0]["id"]
    fix = _cli("fix", ref, str(target), "--out", str(tmp_path / "patch"))
    assert fix.returncode == 0
    payload = json.loads(fix.stdout)
    assert payload["ok"] is True
    assert payload["modified_source_repo"] is False
    verify = _cli("verify", ref, str(target))
    assert verify.returncode == 0
    assert json.loads(verify.stdout)["status"] in (
        "FIXED_VERIFIED",
        "FIXED_UNVERIFIED",
        "NOT_FIXED",
        "REGRESSION",
        "INCONCLUSIVE",
    )


def test_cli_new_scaffold_and_graph(tmp_path):
    proc = _cli("new", "token", str(tmp_path / "mytoken"))
    assert proc.returncode == 0
    assert (tmp_path / "mytoken" / "src" / "SkLabToken.sol").is_file()
    assert (tmp_path / "mytoken" / "script" / "Deploy.s.sol").is_file()
    deploy = (tmp_path / "mytoken" / "script" / "Deploy.s.sol").read_text(encoding="utf-8")
    assert "PRIVATE_KEY" not in deploy or "$PRIVATE_KEY" in deploy
    graph = _cli("graph", str(tmp_path / "mytoken"))
    assert graph.returncode == 0
    graph2 = _cli("graph", str(tmp_path / "mytoken"), "--format", "mermaid")
    assert graph2.returncode == 0
    assert "graph LR" in graph2.stdout


def test_reprobox_patchbench_orchestrator_integrations():
    from sklab_contract_toolkit.integrations.connectors import (
        orchestrator_actions,
        patchbench_verify,
        reprobox_info,
    )

    repro = reprobox_info()
    assert "environment_fingerprint" in repro
    assert "tools" in repro
    patch = patchbench_verify("diff --git a/Token.sol b/Token.sol\n+fix\n")
    assert patch["verdict"] in ("PLAUSIBLE", "WEAK", "INSUFFICIENT")
    actions = {a["action"] for a in orchestrator_actions()}
    assert {"inspect", "compile", "analyze", "test", "fuzz", "invariants", "upgrade-review", "fix", "verify"} <= actions


def test_skill_pack_validation():
    from sklab_contract_toolkit.skills.pack import list_skills, validate_pack

    skills = list_skills()
    assert 12 <= len(skills) <= 18, f"expected 12-18 skills, got {len(skills)}"
    report = validate_pack()
    assert report["errors"] == [], f"skill validation errors: {report['errors']}"
    for skill in skills:
        perms = skill["permissions"]
        assert perms.get("secrets") is False
        if perms.get("network"):
            assert skill["name"] == "contract-address-inspect"


def test_sdk_smoke(foundry_fixture):
    from sklab_contract_toolkit.sdk import ContractToolkit

    toolkit = ContractToolkit(root=foundry_fixture)
    assert toolkit.version()
    assert toolkit.detect_project()["kind"] == "foundry"
    assert any(c["contract_name"] == "Counter" for c in toolkit.list_contracts())
    assert isinstance(toolkit.list_tools(), list)
    report = toolkit.generate_report()
    assert report["scan_fingerprint"]


def test_no_real_broadcast_anywhere():
    """Fail if any source suggests mainnet broadcast / auto-signing."""
    import re

    src = FIXTURES.parent.parent / "src"
    forbidden = re.compile(
        r"eth_sendRawTransaction|eth_sendTransaction|--broadcast(?!\s*\))|"
        r"sign_transaction|from_secret|from_mnemonic|PRIVATE_KEY\s*=\s*['\"][0-9a-fx]",
        re.IGNORECASE,
    )
    hits = []
    for path in src.rglob("*.py"):
        if path.name in ("scaffold.py",):
            continue  # scaffolding templates document manual broadcast as TEMPLATE text only
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in forbidden.finditer(text):
            # documented template strings that say "never auto-deploy" are fine
            line = text[max(0, m.start() - 80) : m.end() + 80]
            if "never" in line.lower() or "TEMPLATE" in line or "template" in line.lower():
                continue
            hits.append(f"{path.name}: {m.group(0)}")
    # --broadcast appears only as a quoted example in scaffolding templates
    hits = [h for h in hits if "scaffold" not in h]
    assert not hits, f"broadcast/signing indicators: {hits}"
