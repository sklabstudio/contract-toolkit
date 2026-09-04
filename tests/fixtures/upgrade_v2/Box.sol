// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Box - upgrade dogfood v2 (INCOMPATIBLE: inserted admin before owner)
contract Box {
    uint256 public total;
    address public admin;
    address public owner;
    uint256 public extra;

    function initialize(address owner_) external {
        owner = owner_;
    }

    function set(uint256 value) external {
        total = value;
    }

    function setAdmin(address next) external {
        admin = next;
    }
}
