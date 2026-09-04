"""Contract category classification — workflow aid, not perfect semantics."""

from __future__ import annotations

import re

from sklab_contract_toolkit.models.contract import ContractModel

_CATEGORY_SIGNALS: list[tuple[str, list[str], float]] = [
    (
        "PROXY",
        [r"TransparentUpgradeableProxy|UUPSUpgradeable|BeaconProxy|upgradeTo|delegatecall|implementation\(\)"],
        3.0,
    ),
    ("VAULT", [r"ERC4626|convertToShares|totalAssets|previewDeposit|shares?\b.*assets?"], 3.0),
    ("STAKING", [r"\bstak\w*|\breward\w*|\bunstak\w*|RewardsDistribution|earned\("], 2.5),
    ("VESTING", [r"\bvest\w*|VestingWallet|vestingSchedule|\bcliff\b"], 2.5),
    ("AIRDROP", [r"\bairdrop\b|MerkleProof|claim\(|merkleRoot"], 2.5),
    ("PRESALE", [r"\bpresale\b|\bwhitelist\b|salePrice|buyTokens"], 2.5),
    ("ESCROW", [r"\bescrow\b|arbiter|releaseFunds|refund\("], 2.0),
    ("MARKETPLACE", [r"marketplace|listItem|buyItem|sellOrder|OrderBook"], 2.0),
    ("TREASURY", [r"\btreasury\b|multisig|GnosisSafe|disburse"], 2.0),
    ("GOVERNANCE", [r"\bgovern\w*|Governor|propos\w*|vot\w*|quorum|timelock"], 2.5),
    ("TIMELOCK", [r"Timelock|schedule\(|execute\(bytes|delay\(\)|ETA"], 2.5),
    ("FACTORY", [r"\bfactory\b|create2|Clones|clone\(|deployProxy"], 2.0),
    ("ORACLE_INTEGRATION", [r"AggregatorV3Interface|latestRoundData|Chainlink|priceFeed|IOracle"], 2.5),
    ("AMM", [r"\bswap\b|addLiquidity|removeLiquidity|getReserves|IUniswap|pair"], 2.5),
    ("LENDING", [r"\bborrow\b|\blend\b|collateral|liquidat\w*|healthFactor"], 2.5),
    ("REWARD_DISTRIBUTOR", [r"distribut\w*reward|dividend|stakingRewards|notifyReward"], 2.0),
    ("PAYMENT", [r"\bpay\b|splitPayment|PullPayment|withdrawPayments|escrow"], 1.5),
    ("TOKEN", [r"ERC20|totalSupply|transferFrom|_mint|_burn"], 2.0),
    ("NFT", [r"ERC721|ERC1155|tokenURI|safeMint|ownerOf"], 2.0),
]


def classify_contract(model: ContractModel) -> str:
    name_blob = model.contract_name + " " + " ".join(model.inheritance)
    fn_blob = " ".join(f.name for f in model.functions)
    blob = f"{name_blob} {fn_blob}"
    scores: dict[str, float] = {}
    for category, patterns, weight in _CATEGORY_SIGNALS:
        for pattern in patterns:
            if re.search(pattern, blob, re.IGNORECASE):
                scores[category] = scores.get(category, 0.0) + weight
                break
    # standards-informed boosts
    stds = {s.get("standard") for s in model.standards if isinstance(s, dict)}
    if "ERC-20" in stds:
        scores["TOKEN"] = scores.get("TOKEN", 0.0) + 1.0
    if stds & {"ERC-721", "ERC-1155"}:
        scores["NFT"] = scores.get("NFT", 0.0) + 1.0
    if "ERC-4626" in stds:
        scores["VAULT"] = scores.get("VAULT", 0.0) + 1.0
    if not scores:
        return "CUSTOM"
    return max(scores, key=lambda k: scores[k])
