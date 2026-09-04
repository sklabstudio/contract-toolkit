// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title OriginAuth - tx.origin authorization fixture
contract OriginAuth {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // VULN: tx.origin authorization (spoofable via intermediary contract)
    function withdraw(uint256 amount) external {
        require(tx.origin == owner, "not owner");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
