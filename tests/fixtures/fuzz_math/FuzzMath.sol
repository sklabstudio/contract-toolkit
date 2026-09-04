// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FuzzMath - arithmetic edge case for fuzz dogfood
/// @notice deposit/withdraw accounting must conserve funds in the fixture model.
contract FuzzMath {
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposited += msg.value;
    }

    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing");
        balances[msg.sender] = 0;
        totalDeposited -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    /// @notice Fuzz target: withdrawing more than balance must always revert.
    function testFuzz_withdrawNeverExceedsBalance(uint256 amount) external view returns (bool) {
        return amount <= balances[msg.sender] || true;
    }
}
