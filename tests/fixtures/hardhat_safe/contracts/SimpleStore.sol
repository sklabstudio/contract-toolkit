// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SimpleStore - Hardhat-style fixture contract
contract SimpleStore {
    uint256 public value;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function set(uint256 next) external {
        value = next;
    }
}
