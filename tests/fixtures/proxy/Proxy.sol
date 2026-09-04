// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BoxProxy - UUPS-style upgradeable fixture (gated _authorizeUpgrade)
contract BoxProxy {
    uint256 public total;
    address public owner;
    address private _implementation;
    bytes32 private constant _ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    uint256[50] private __gap;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function initialize(address owner_) external {
        require(owner == address(0), "already initialized");
        owner = owner_;
    }

    function implementation() external view returns (address) {
        return _implementation;
    }

    function upgradeTo(address next) external onlyOwner {
        _authorizeUpgrade(next);
        _implementation = next;
    }

    function upgradeToAndCall(address next, bytes calldata data) external onlyOwner {
        _authorizeUpgrade(next);
        _implementation = next;
        (bool ok, ) = next.delegatecall(data);
        require(ok, "call failed");
    }

    function proxiableUUID() external pure returns (bytes32) {
        return 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    }

    function _authorizeUpgrade(address) internal view onlyOwner {}
}
