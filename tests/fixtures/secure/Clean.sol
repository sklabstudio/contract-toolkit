// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CleanRoom - secure fixture (expected: no HIGH findings)
contract CleanRoom {
    address public owner;
    bool private _locked;
    uint256 public counter;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function increment() external nonReentrant {
        counter += 1;
    }

    function transferOwnership(address next) external onlyOwner {
        require(next != address(0), "zero address");
        owner = next;
    }
}
