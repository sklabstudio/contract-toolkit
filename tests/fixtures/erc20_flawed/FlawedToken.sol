// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FlawedToken - public mint without authorization (access-control dogfood)
contract FlawedToken {
    string public name = "Flawed Token";
    string public symbol = "FLAW";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address public owner;
    mapping(address => uint256) public balanceOf;
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        owner = msg.sender;
    }

    // VULN: anyone can mint arbitrary amounts — public mint without authorization.
    function mint(address to, uint256 value) external {
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "insufficient");
        unchecked {
            balanceOf[msg.sender] -= value;
            balanceOf[to] += value;
        }
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function balanceOf_(address user) external view returns (uint256) {
        return balanceOf[user];
    }

    function allowance(address, address) external pure returns (uint256) { return 0; }
    function approve(address, uint256) external pure returns (bool) { return true; }
    function transferFrom(address, address, uint256) external pure returns (bool) { return true; }
}
