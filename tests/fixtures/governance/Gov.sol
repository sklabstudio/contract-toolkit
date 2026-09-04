// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CivicGovernor - role-heavy governance fixture
contract CivicGovernor {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    address public timelock;
    bool public paused;
    mapping(bytes32 => mapping(address => bool)) private _roles;

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "missing role");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    constructor(address timelock_) {
        timelock = timelock_;
        _roles[DEFAULT_ADMIN_ROLE][msg.sender] = true;
    }

    function hasRole(bytes32 role, address user) external view returns (bool) {
        return _roles[role][user];
    }

    function grantRole(bytes32 role, address user) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _roles[role][user] = true;
    }

    function revokeRole(bytes32 role, address user) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _roles[role][user] = false;
    }

    function propose(bytes calldata data) external onlyRole(PROPOSER_ROLE) whenNotPaused returns (bytes32) {
        return keccak256(data);
    }

    function execute(bytes calldata data) external onlyRole(EXECUTOR_ROLE) whenNotPaused {
        (bool ok, ) = timelock.call(data);
        require(ok, "exec failed");
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        paused = true;
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        paused = false;
    }

    function paused_() external view returns (bool) {
        return paused;
    }
}
