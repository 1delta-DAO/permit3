// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Permit3} from "../../src/permit3/Permit3.sol";
import {IPermit3} from "../../src/interfaces/IPermit3.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {Permit3Signature} from "../utils/Permit3Signature.sol";

/// @notice Common setup shared by all Permit3 test files: one Permit3
///         instance, two tokens, two users each with pre-approved balances.
abstract contract Permit3Test is Test, Permit3Signature {
    Permit3 internal permit3;

    MockERC20 internal token0;
    MockERC20 internal token1;

    uint256 internal constant alicePk = 0xA11CE;
    uint256 internal constant bobPk = 0xB0B;
    address internal alice = vm.addr(alicePk);
    address internal bob = vm.addr(bobPk);

    uint160 internal constant DEFAULT_AMOUNT = 1e18;
    uint48 internal constant DEFAULT_NONCE = 0;
    uint48 internal defaultExpiration;
    uint256 internal defaultDeadline;

    bytes32 internal DOMAIN_SEPARATOR;

    function _baseSetup() internal {
        permit3 = new Permit3();
        DOMAIN_SEPARATOR = permit3.DOMAIN_SEPARATOR();

        token0 = new MockERC20();
        token1 = new MockERC20();

        defaultExpiration = uint48(block.timestamp + 1 days);
        defaultDeadline = block.timestamp + 1 hours;

        token0.mint(alice, 1000e18);
        token1.mint(alice, 1000e18);
        token0.mint(bob, 1000e18);
        token1.mint(bob, 1000e18);

        vm.prank(alice);
        token0.approve(address(permit3), type(uint256).max);
        vm.prank(alice);
        token1.approve(address(permit3), type(uint256).max);
        vm.prank(bob);
        token0.approve(address(permit3), type(uint256).max);
    }
}
