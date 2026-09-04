// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Counter - minimal Foundry-style fixture contract
contract Counter {
    uint256 public number;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setNumber(uint256 value) external {
        number = value;
    }

    function increment() external {
        number += 1;
    }
}
