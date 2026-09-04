// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title YieldVault - ERC-4626 style fixture
contract YieldVault {
    address public asset;
    address public admin;
    uint256 public totalAssets;
    uint256 public totalShares;
    uint256 public feeBps;
    mapping(address => uint256) public balanceOf;

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    constructor(address asset_) {
        asset = asset_;
        admin = msg.sender;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalShares == 0 || totalAssets == 0) return assets;
        return (assets * totalShares) / totalAssets;
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        if (totalShares == 0 || totalAssets == 0) return shares;
        return (shares * totalAssets) / totalShares;
    }

    function maxDeposit(address) external pure returns (uint256) { return type(uint256).max; }
    function previewDeposit(uint256 assets) external view returns (uint256) {
        return convertToShares(assets);
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        totalAssets += assets;
        totalShares += shares;
        balanceOf[receiver] += shares;
    }

    function maxWithdraw(address owner_) external view returns (uint256) {
        return convertToAssets(balanceOf[owner_]);
    }

    function previewWithdraw(uint256 assets) external view returns (uint256) {
        return convertToShares(assets);
    }

    function withdraw(uint256 assets, address receiver, address owner_) external returns (uint256 shares) {
        require(msg.sender == owner_, "not owner");
        shares = convertToShares(assets);
        unchecked {
            balanceOf[owner_] -= shares;
        }
        totalAssets -= assets;
        totalShares -= shares;
        receiver;
    }

    function setFee(uint256 bps) external onlyAdmin {
        require(bps <= 10000, "fee exceeds 10000 bps");
        feeBps = bps;
    }
}
