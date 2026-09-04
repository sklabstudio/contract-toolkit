// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title RewardPool - staking fixture
contract RewardPool {
    address public owner;
    uint256 public rewardRate = 1e12;
    uint256 public totalStaked;
    uint256 public constant MAX_STAKE = 1_000_000 ether;
    mapping(address => uint256) public staked;
    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function stake() external payable {
        require(msg.value + totalStaked <= MAX_STAKE, "cap");
        staked[msg.sender] += msg.value;
        totalStaked += msg.value;
        emit Staked(msg.sender, msg.value);
    }

    function unstake(uint256 amount) external {
        require(staked[msg.sender] >= amount, "insufficient");
        staked[msg.sender] -= amount;
        totalStaked -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Unstaked(msg.sender, amount);
    }

    function earned(address user) external view returns (uint256) {
        return (staked[user] * rewardRate) / 1e18;
    }

    function setRewardRate(uint256 rate) external onlyOwner {
        rewardRate = rate;
    }
}
