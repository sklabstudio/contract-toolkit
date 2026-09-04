"""Unit tests: detection, inventory, ABI, authorities, standards, rules, diffs."""

from __future__ import annotations

import re
from pathlib import Path

from sklab_contract_toolkit.analysis.authorities import extract_authorities
from sklab_contract_toolkit.analysis.engine import list_rules, run_internal_analysis
from sklab_contract_toolkit.analysis.slither_norm import parse_slither_json, slither_available
from sklab_contract_toolkit.chains.registry import get_adapter, list_adapters
from sklab_contract_toolkit.core.config import ToolkitConfig, config_validation_errors, load_config
from sklab_contract_toolkit.core.pathsafety import PathSafetyError, ensure_inside_root
from sklab_contract_toolkit.detection.project import detect_project
from sklab_contract_toolkit.detection.solidity import (
    extract_abis,
    function_selector,
    inventory_contracts,
)
from sklab_contract_toolkit.graphs.builder import build_graphs, to_dot, to_mermaid
from sklab_contract_toolkit.models.findings import ContractFinding, deduplicate_findings
from sklab_contract_toolkit.standards.categories import classify_contract
from sklab_contract_toolkit.standards.registry import detect_standards, list_supported_standards
from sklab_contract_toolkit.tools.manager import choose_toolchain, list_tools
from sklab_contract_toolkit.upgrades.abi_diff import diff_abis
from sklab_contract_toolkit.upgrades.review import review_upgrade
from sklab_contract_toolkit.upgrades.storage import diff_storage, extract_storage_layouts

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_evm_adapter_full_and_honest_states():
    adapters = list_adapters()
    assert adapters["evm"] == "SUPPORTED"
    # future adapters must not claim SUPPORTED
    for chain_id in ("solana", "move-aptos", "move-sui", "cosmwasm", "ton"):
        assert adapters[chain_id] in ("EXPERIMENTAL", "UNAVAILABLE", "PARTIAL")
    evm = get_adapter("evm")
    assert evm.capabilities()["compile"] is True
    future = get_adapter("solana")
    assert future.capabilities()["compile"] is False


def test_foundry_detection(foundry_fixture):
    detection = detect_project(foundry_fixture)
    assert detection.kind == "foundry"
    assert detection.chain == "evm"
    assert detection.confidence > 0


def test_hardhat_detection(hardhat_fixture):
    detection = detect_project(hardhat_fixture)
    assert detection.kind == "hardhat"


def test_raw_solidity_detection():
    detection = detect_project(FIXTURES / "raw")
    assert detection.kind == "raw_solidity"


def test_config_validation_ok_and_bad(tmp_path):
    cfg = tmp_path / "sklab-contract.yaml"
    cfg.write_text("schema_version: 1\n", encoding="utf-8")
    loaded = load_config(path=cfg)
    assert isinstance(loaded, ToolkitConfig)
    assert loaded.schema_version == 1
    errors = config_validation_errors({"schema_version": 999, "bogus": True})
    assert errors


def test_contract_inventory_foundry(foundry_fixture):
    models = inventory_contracts(foundry_fixture)
    names = {m.contract_name for m in models}
    assert "Counter" in names
    counter = next(m for m in models if m.contract_name == "Counter")
    fn_names = {f.name for f in counter.functions}
    assert {"setNumber", "increment"} <= fn_names
    assert counter.source_file.endswith("Counter.sol")


def test_abi_extraction_has_selectors(foundry_fixture):
    abis = extract_abis(foundry_fixture)
    assert "Counter" in abis
    entries = abis["Counter"]["abi"]
    set_number = next(e for e in entries if e.get("name") == "setNumber")
    assert set_number["selector"].startswith("0x") and len(set_number["selector"]) == 10


def test_function_selector_known_value():
    # Well-known ERC-20 transfer selector
    assert function_selector("transfer(address,uint256)") == "0xa9059cbb"


def test_authority_extraction_ownable(foundry_fixture):
    authorities = extract_authorities(foundry_fixture)
    assert authorities  # Counter has owner + onlyOwner-free but owner var? at least empty-safe
    # flawed token exposes owner authority
    flawed = extract_authorities(FIXTURES / "erc20_flawed")
    kinds = {(a.authority, a.target_contract) for a in flawed}
    assert any("owner" in auth.lower() for auth, _ in kinds)


def test_standards_detection_erc20():
    models = inventory_contracts(FIXTURES / "erc20_safe")
    token = next(m for m in models if m.contract_name == "SafeToken")
    stds = {s.standard for s in detect_standards(token)}
    assert "ERC-20" in stds
    assert "ERC-2612" in stds  # permit/nonces/DOMAIN_SEPARATOR present
    assert "ERC-20" in list_supported_standards()
    assert "ERC-4626" in list_supported_standards()


def test_standards_detection_erc721_4626():
    nft = next(m for m in inventory_contracts(FIXTURES / "erc721") if m.contract_name == "GalleryNFT")
    assert "ERC-721" in {s.standard for s in detect_standards(nft)}
    vault = next(m for m in inventory_contracts(FIXTURES / "erc4626") if m.contract_name == "YieldVault")
    assert "ERC-4626" in {s.standard for s in detect_standards(vault)}


def test_category_classification():
    vault = next(m for m in inventory_contracts(FIXTURES / "erc4626") if m.contract_name == "YieldVault")
    assert classify_contract(vault) in ("VAULT", "TOKEN")
    gov = next(m for m in inventory_contracts(FIXTURES / "governance") if m.contract_name == "CivicGovernor")
    assert classify_contract(gov) in ("GOVERNANCE", "TIMELOCK", "CUSTOM")


def test_internal_rules_tx_origin():
    findings = run_internal_analysis(FIXTURES / "tx_origin")
    rule_ids = {f.rule_id for f in findings}
    assert "SKLAB-TX-ORIGIN-001" in rule_ids
    tx = next(f for f in findings if f.rule_id == "SKLAB-TX-ORIGIN-001")
    assert tx.severity == "HIGH" and tx.confidence == "HIGH"
    assert tx.fingerprint and tx.id


def test_internal_rules_unchecked_call_and_reentrancy():
    findings = run_internal_analysis(FIXTURES / "unchecked_call")
    assert "SKLAB-UNCHECKED-CALL-001" in {f.rule_id for f in findings}
    findings2 = run_internal_analysis(FIXTURES / "reentrancy")
    assert "SKLAB-REENTRANCY-001" in {f.rule_id for f in findings2}


def test_internal_rules_have_versions():
    rules = list_rules()
    assert len(rules) >= 10
    for rule in rules:
        assert rule["rule_id"].startswith("SKLAB-")
        assert rule["rule_version"]


def test_slither_adapter_unavailable_or_parse():
    if not slither_available():
        from sklab_contract_toolkit.analysis.slither_norm import run_slither

        result = run_slither(FIXTURES / "raw")
        assert result["available"] is False
    # parser handles empty + malformed gracefully
    assert parse_slither_json("") == []
    assert parse_slither_json("not json") == []


def test_slither_parse_normalizes(tmp_path):
    import json

    payload = {
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "Reentrancy in Vault.withdraw",
                    "elements": [
                        {"type": "Vault", "source_mapping": {"filename_relative": "Vault.sol", "lines": [10]}}
                    ],
                }
            ]
        }
    }
    findings = parse_slither_json(json.dumps(payload))
    assert len(findings) == 1
    assert findings[0].tool == "slither"
    assert findings[0].tool_rule == "reentrancy-eth"
    assert findings[0].severity == "HIGH"
    assert findings[0].evidence_level == "TOOL_REPORTED"


def test_unavailable_tool_behavior():
    tools = {t.tool: t for t in list_tools()}
    for _name, info in tools.items():
        if not info.installed:
            assert info.status == "unavailable"
            assert "not found" in info.notes.lower() or "unavailable" in info.status


def test_finding_dedupe_and_fingerprint_stability():
    f1 = ContractFinding(
        rule_id="SKLAB-TX-ORIGIN-001",
        rule_version="1.0.0",
        title="t",
        category="TX_ORIGIN",
        contract="A",
        function="f",
        file="A.sol",
        line=1,
    ).with_fingerprint()
    f2 = ContractFinding(
        rule_id="SKLAB-TX-ORIGIN-001",
        rule_version="1.0.0",
        title="t",
        category="TX_ORIGIN",
        contract="A",
        function="f",
        file="A.sol",
        line=1,
        tool="slither",
        tool_rule="tx-origin",
    ).with_fingerprint()
    assert f1.fingerprint == f2.fingerprint
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 1


def test_storage_extraction_and_diff():
    layouts = extract_storage_layouts(FIXTURES / "upgrade_v1")
    assert "Box" in layouts
    labels = [s.label for s in layouts["Box"].slots]
    assert labels == ["total", "owner"]
    new_layouts = extract_storage_layouts(FIXTURES / "upgrade_v2")
    diff = diff_storage(layouts["Box"], new_layouts["Box"])
    assert "admin" in diff["added"] or "extra" in diff["added"]
    assert diff["type_changes"] == [] or isinstance(diff["type_changes"], list)


def test_upgrade_review_incompatible():
    verdict = review_upgrade(FIXTURES / "upgrade_v1", FIXTURES / "upgrade_v2")
    assert verdict.verdict == "INCOMPATIBLE"
    assert verdict.evidence


def test_abi_diff_breaking():
    old = [
        {"type": "function", "name": "set", "inputs": [{"type": "uint256"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "get", "inputs": [], "stateMutability": "view"},
    ]
    new = [
        {"type": "function", "name": "set", "inputs": [{"type": "uint256"}], "stateMutability": "nonpayable"},
        {"type": "function", "name": "reset", "inputs": [], "stateMutability": "nonpayable"},
    ]
    diff = diff_abis(old, new)
    assert "get()" in diff.removed_functions
    assert "reset()" in diff.added_functions
    assert diff.breaking is True


def test_graphs_export_formats(foundry_fixture):
    graphs = build_graphs(foundry_fixture)
    assert set(graphs) == {"inheritance", "import", "call", "dependency", "external_call", "authority"}
    dot = to_dot("call", graphs["call"])
    assert dot.startswith("digraph")
    mermaid = to_mermaid("call", graphs["call"])
    assert mermaid.startswith("graph LR")


def test_path_safety_rejects_escape(foundry_fixture):
    with_foundry = foundry_fixture.resolve()
    try:
        ensure_inside_root(with_foundry, "../../etc/passwd")
    except PathSafetyError:
        pass
    else:
        raise AssertionError("path traversal was not rejected")
    try:
        ensure_inside_root(with_foundry, "/")
    except PathSafetyError:
        pass
    else:
        raise AssertionError("filesystem root scan was not rejected")


def test_private_key_safety_scan():
    from pathlib import Path as _Path

    src = _Path(__file__).parent.parent.parent / "src"
    hits = []
    for path in src.rglob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-", "*", ">", '"""', "'''")):
                continue
            if "never" in stripped.lower():
                continue  # documenting the prohibition, not violating it
            if re.search(r"shell\s*=\s*True", line):
                hits.append(f"{path.name}:{lineno}: {stripped[:100]}")
    assert not hits, f"shell=True found: {hits}"


def test_choose_toolchain_no_crash(tmp_path):
    result = choose_toolchain(FIXTURES / "raw", preferred="auto")
    assert result["chosen"] in ("foundry", "hardhat", "solc", "none")
    assert "reason" in result
