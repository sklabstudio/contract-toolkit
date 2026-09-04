// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeToken - well-behaved ERC-20 fixture (expected: minimal findings)
contract SafeToken {
    string public name = "Safe Token";
    string public symbol = "SAFE";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    uint256 public constant MAX_SUPPLY = 1_000_000 * 1e18;
    address public owner;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
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

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(balanceOf[from] >= value, "insufficient");
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= value, "allowance");
        unchecked {
            allowance[from][msg.sender] = allowed - value;
            balanceOf[from] -= value;
            balanceOf[to] += value;
        }
        emit Transfer(from, to, value);
        return true;
    }

    function permit(address, address, uint256, uint256, uint8, bytes32, bytes32) external pure {}
    function nonces(address) external pure returns (uint256) { return 0; }
    function DOMAIN_SEPARATOR() external pure returns (bytes32) { return bytes32(0); }
}
