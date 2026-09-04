// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Box.sol";

contract BoxConsumer {
    Box public box;
    constructor(address box_) {
        box = Box(box_);
    }
}
