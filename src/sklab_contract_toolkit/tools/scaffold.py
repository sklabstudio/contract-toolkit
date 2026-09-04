"""Project scaffolding: token / nft / vault / staking / custom templates.

Templates are authored by SKLab, use well-known public standards, and expose
assumptions (admin powers, supply, upgradeability). No live keys, no deploy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

SPDX = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n"

_TOKEN = (
    SPDX
    + """
/// @title SkLabToken - ERC-20 style template (educational, unaudited)
/// @notice Assumptions: admin can mint up to MAX_SUPPLY; no pause; not upgradeable.
contract SkLabToken {
    string public name = "SkLab Token";
    string public symbol = "SKLAB";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    uint256 public constant MAX_SUPPLY = 1_000_000 * 1e18;
    address public owner;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    constructor() { owner = msg.sender; }
    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "insufficient");
        unchecked { balanceOf[msg.sender] -= value; balanceOf[to] += value; }
        emit Transfer(msg.sender, to, value);
        return true;
    }
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(balanceOf[from] >= value, "insufficient");
        require(allowance[from][msg.sender] >= value, "allowance");
        unchecked {
            allowance[from][msg.sender] -= value;
            balanceOf[from] -= value;
            balanceOf[to] += value;
        }
        emit Transfer(from, to, value);
        return true;
    }
    function mint(address to, uint256 value) external onlyOwner {
        require(totalSupply + value <= MAX_SUPPLY, "cap exceeded");
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }
}
"""
)

_NFT = (
    SPDX
    + """
/// @title SkLabNFT - ERC-721 style template (educational, unaudited)
/// @notice Assumptions: owner-gated minting; sequential token IDs; not upgradeable.
contract SkLabNFT {
    string public name = "SkLab NFT";
    string public symbol = "SKLABNFT";
    uint256 public nextTokenId = 1;
    address public owner;
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    constructor() { owner = msg.sender; }
    function mint(address to) external onlyOwner returns (uint256 tokenId) {
        tokenId = nextTokenId++;
        ownerOf[tokenId] = to;
        balanceOf[to] += 1;
        emit Transfer(address(0), to, tokenId);
    }
    function transferFrom(address from, address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == from, "not owner");
        require(msg.sender == from, "not approved");
        ownerOf[tokenId] = to;
        unchecked { balanceOf[from] -= 1; balanceOf[to] += 1; }
        emit Transfer(from, to, tokenId);
    }
}
"""
)

_VAULT = (
    SPDX
    + """
/// @title SkLabVault - ERC-4626 style template (educational, unaudited)
/// @notice Assumptions: single admin sets fees in BPS (<=10000); rounding favors the vault.
contract SkLabVault {
    address public asset;
    address public admin;
    uint256 public totalAssets;
    uint256 public totalShares;
    uint256 public feeBps;
    mapping(address => uint256) public balanceOf;
    modifier onlyAdmin() { require(msg.sender == admin, "not admin"); _; }
    constructor(address asset_) { asset = asset_; admin = msg.sender; }
    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalShares == 0 || totalAssets == 0) return assets;
        return (assets * totalShares) / totalAssets;
    }
    function convertToAssets(uint256 shares) public view returns (uint256) {
        if (totalShares == 0 || totalAssets == 0) return shares;
        return (shares * totalAssets) / totalShares;
    }
    function previewDeposit(uint256 assets) external view returns (uint256) {
        return convertToShares(assets);
    }
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        totalAssets += assets;
        totalShares += shares;
        balanceOf[receiver] += shares;
    }
    function previewWithdraw(uint256 assets) external view returns (uint256) {
        return convertToShares(assets);
    }
    function withdraw(uint256 assets, address receiver, address owner_) external returns (uint256 shares) {
        require(msg.sender == owner_, "not owner");
        shares = convertToShares(assets);
        unchecked { balanceOf[owner_] -= shares; }
        totalAssets -= assets;
        totalShares -= shares;
    }
    function setFee(uint256 bps) external onlyAdmin {
        require(bps <= 10000, "fee exceeds 10000 bps");
        feeBps = bps;
    }
}
"""
)

_STAKING = (
    SPDX
    + """
/// @title SkLabStaking - staking template (educational, unaudited)
/// @notice Assumptions: fixed rewardRate per second; owner funds rewards; no lockup.
contract SkLabStaking {
    address public owner;
    uint256 public rewardRate;
    uint256 public totalStaked;
    mapping(address => uint256) public staked;
    mapping(address => uint256) public rewardDebt;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    constructor(uint256 rewardRate_) { owner = msg.sender; rewardRate = rewardRate_; }
    function stake() external payable {
        staked[msg.sender] += msg.value;
        totalStaked += msg.value;
    }
    function unstake(uint256 amount) external {
        require(staked[msg.sender] >= amount, "insufficient");
        staked[msg.sender] -= amount;
        totalStaked -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
    function earned(address user) external view returns (uint256) {
        return (staked[user] * rewardRate) / 1e18;
    }
    function setRewardRate(uint256 rate) external onlyOwner { rewardRate = rate; }
}
"""
)

_CUSTOM = (
    SPDX
    + """
/// @title SkLabCustom - minimal starting point (educational, unaudited)
/// @notice Assumptions: single owner; document every privileged function you add.
contract SkLabCustom {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    constructor() { owner = msg.sender; }
    function transferOwnership(address next) external onlyOwner {
        require(next != address(0), "zero address");
        owner = next;
    }
}
"""
)

_TEST_TMPL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "../src/{Contract}.sol";
contract {Contract}Test {{
    {Contract} internal target;
    function setUp() public {{ target = new {Contract}({ctor}); }}
    function test_smoke() public {{
        require(address(target) != address(0), "deploy failed");
    }}
}}
"""

_FOUNDRY_TOML = """[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc_version = "0.8.24"
"""

_README_TMPL = """# {Name}

Scaffolded with `sklab-contract new {kind}`. Educational template — unaudited.

## Assumptions

{assumptions}

## Scripts

- `sklab-contract inspect .`
- `sklab-contract compile .`
- `sklab-contract test .`
- `sklab-contract analyze .`

## Deployment

Deployment is intentionally manual. See `script/Deploy.s.sol` for a TEMPLATE
that never contains private keys (uses `$PRIVATE_KEY` placeholder only).
"""

_DEPLOY_TMPL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// Deployment TEMPLATE — never commits keys. Broadcast manually, e.g.:
//   forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
// This toolkit never auto-deploys.
"""

_CHECKLIST = """# Verification checklist

- [ ] Compiler version pinned
- [ ] Tests pass (`sklab-contract test .`)
- [ ] Static analysis reviewed (`sklab-contract analyze .`)
- [ ] Authorities documented (owner/admin/minter/pauser)
- [ ] Upgrade/storage review completed for upgrades
- [ ] ABI diff reviewed for releases
- [ ] No private keys committed
"""

_ASSUMPTIONS = {
    "token": "Admin powers: mint (capped). Supply: capped at 1M. Upgradeability: disabled.",
    "nft": "Admin powers: mint. Supply: unbounded sequential IDs. Upgradeability: disabled.",
    "vault": "Admin powers: setFee (<=10000 bps). Rounding: favors vault. Upgradeability: disabled.",
    "staking": "Admin powers: setRewardRate. Rewards: fixed rate. Upgradeability: disabled.",
    "custom": "Admin powers: transferOwnership. Upgradeability: disabled.",
}

_TEMPLATES = {
    "token": (_TOKEN, "SkLabToken", ""),
    "nft": (_NFT, "SkLabNFT", ""),
    "vault": (_VAULT, "SkLabVault", "address(0)"),
    "staking": (_STAKING, "SkLabStaking", "1e12"),
    "custom": (_CUSTOM, "SkLabCustom", ""),
}


def scaffold(kind: str, dest: Path | str, name: str | None = None) -> dict[str, Any]:
    kind = kind.lower()
    if kind not in _TEMPLATES:
        raise ValueError(f"Unknown template kind: {kind} (token|nft|vault|staking|custom)")
    dest_path = Path(dest).resolve()
    dest_path.mkdir(parents=True, exist_ok=True)
    source, contract, ctor = _TEMPLATES[kind]
    display = name or contract
    files: list[str] = []
    for rel, content in [
        (f"src/{contract}.sol", source),
        (f"test/{contract}.t.sol", _TEST_TMPL.format(Contract=contract, ctor=ctor)),
        ("foundry.toml", _FOUNDRY_TOML),
        ("README.md", _README_TMPL.format(Name=display, kind=kind, assumptions=_ASSUMPTIONS[kind])),
        ("script/Deploy.s.sol", _DEPLOY_TMPL),
        ("verification-checklist.md", _CHECKLIST),
    ]:
        target = dest_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        files.append(rel)
    return {
        "kind": kind,
        "contract": contract,
        "dir": str(dest_path),
        "files": files,
        "assumptions": _ASSUMPTIONS[kind],
    }
