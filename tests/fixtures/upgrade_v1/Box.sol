// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Box - upgrade dogfood v1 (total, owner)
contract Box {
    uint256 public total;
    address public owner;

    function initialize(address owner_) external {
        owner = owner_;
    }

    function set(uint256 value) external {
        total = value;
    }
}
