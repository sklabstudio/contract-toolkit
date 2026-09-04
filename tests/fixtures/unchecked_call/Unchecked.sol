// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CarelessCaller - unchecked low-level call fixture
contract CarelessCaller {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function forward(address target, bytes calldata data) external payable {
        // VULN: unchecked low-level call result
        target.call{value: msg.value}(data);
    }

    function safeForward(address target, bytes calldata data) external payable {
        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "call failed");
    }
}
