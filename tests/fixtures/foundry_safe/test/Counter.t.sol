// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/Counter.sol";

contract CounterTest {
    Counter internal counter;

    function setUp() public {
        counter = new Counter();
    }

    function test_increment() public {
        counter.increment();
        require(counter.number() == 1, "increment failed");
    }

    function testFuzz_setNumber(uint256 value) public {
        counter.setNumber(value);
        require(counter.number() == value, "setNumber failed");
    }

    function invariant_count() public view returns (bool) {
        return counter.number() >= 0;
    }
}
