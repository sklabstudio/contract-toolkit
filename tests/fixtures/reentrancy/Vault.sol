// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ReentrantVault - external call before state change (heuristic dogfood)
contract ReentrantVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        // VULN pattern: external call before state update, no nonReentrant
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
