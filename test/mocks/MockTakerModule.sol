// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ITakerModule} from "../../src/interfaces/ITakerModule.sol";
import {IPermit3} from "../../src/interfaces/IPermit3.sol";
import {MockERC20} from "./MockERC20.sol";

/// @notice Happy-path module: mints a mock "borrow token" to receiver on take.
contract MockTakerModule is ITakerModule {
    address public immutable permit3;
    MockERC20 public immutable borrowToken;

    address public lastOnBehalfOf;
    uint256 public lastAmount;
    address public lastReceiver;
    bytes public lastData;
    uint256 public callCount;

    constructor(address _permit3, address _borrowToken) {
        permit3 = _permit3;
        borrowToken = MockERC20(_borrowToken);
    }

    function takeOnBehalf(address onBehalfOf, uint256 amount, address receiver, bytes calldata data)
        external
        override
    {
        require(msg.sender == permit3, "MockTakerModule: not permit3");
        lastOnBehalfOf = onBehalfOf;
        lastAmount = amount;
        lastReceiver = receiver;
        lastData = data;
        callCount++;
        borrowToken.mint(receiver, amount);
    }
}

/// @notice Module that tries to re-enter Permit3.take — used to prove the
///         reentrancy guard.
contract ReentrantTakerModule is ITakerModule {
    IPermit3 public immutable permit3;

    constructor(address _permit3) {
        permit3 = IPermit3(_permit3);
    }

    function takeOnBehalf(address onBehalfOf, uint256 amount, address, bytes calldata data) external override {
        require(msg.sender == address(permit3), "ReentrantTakerModule: not permit3");
        permit3.take(address(this), onBehalfOf, uint160(amount), address(this), data);
    }
}

/// @notice Module that pulls an ERC20 from the user via Permit3.transferFrom
///         during its take — exercises the combined token+taker flow.
contract PullingTakerModule is ITakerModule {
    IPermit3 public immutable permit3;

    constructor(address _permit3) {
        permit3 = IPermit3(_permit3);
    }

    function takeOnBehalf(address onBehalfOf, uint256 amount, address receiver, bytes calldata data)
        external
        override
    {
        require(msg.sender == address(permit3), "PullingTakerModule: not permit3");
        address token = abi.decode(data, (address));
        permit3.transferFrom(onBehalfOf, receiver, token, uint160(amount));
    }
}
