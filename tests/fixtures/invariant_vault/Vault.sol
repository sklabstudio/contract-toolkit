// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title InvariantVault - explicit invariant fixture (no auto-mined invariants)
/// @notice INVARIANT: sum of modeled balances must equal totalShares under fixture assumptions.
contract InvariantVault {
    mapping(address => uint256) public balances;
    uint256 public totalShares;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalShares += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalShares -= amount;
    }

    /// @notice Explicit invariant: solvency — every balance is backed by totalShares.
    function invariant_solvency() external view returns (bool) {
        return totalShares >= balances[msg.sender];
    }
}
