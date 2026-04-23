// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";

import {Permit3} from "../src/permit3/Permit3.sol";
import {IPermit3} from "../src/interfaces/IPermit3.sol";
import {CometWithdrawModule} from "../src/modules/CometWithdrawModule.sol";

interface ICometExt {
    function supply(address asset, uint256 amount) external;
    function allow(address manager, bool isAllowed_) external;
    function balanceOf(address account) external view returns (uint256);
    function collateralBalanceOf(address account, address asset) external view returns (uint128);
    function baseToken() external view returns (address);
}

/// @notice Fork test: prove CometWithdrawModule actually pulls the base
///         asset out of a Comet position on mainnet, gated only by the
///         Permit3 taker allowance.
///
///         Happy path:
///           1. User supplies USDS into cUSDSv3.
///           2. User flips `comet.allow(module, true)` — boolean, unbounded.
///           3. User approves Permit3 with a 500 USDS cap on (comet, USDS).
///           4. A random caller invokes `permit3.take(...)`.
///           5. 500 USDS lands with the receiver.
///
///         Negative path:
///           Without the per-order Permit3 allowance, `take` reverts on
///           the allowance gate before hitting the module.
contract CometWithdrawModuleForkTest is Test {
    // Mainnet cUSDSv3. (cUSDSv3 / cWETHv3 have isWithdrawPaused=true at
    // current head — cUSDSv3 is actively open for withdrawals.)
    address constant COMET = 0x5D409e56D886231aDAf00c8775665AD0f9897b56;
    address constant USDS = 0xdC035D45d973E3EC169d2276DDab16f1e407384F;

    Permit3 permit3;
    CometWithdrawModule module;

    address user;
    address spender = makeAddr("spender");
    address receiver = makeAddr("receiver");

    bytes data;
    bytes32 ref;

    function setUp() public {
        vm.createSelectFork(vm.envOr("MAINNET_RPC_URL", string("https://ethereum-rpc.publicnode.com")));

        permit3 = new Permit3();
        module = new CometWithdrawModule(address(permit3));

        user = makeAddr("user");

        data = abi.encode(COMET, USDS);
        ref = keccak256(data);

        // Seed the user with USDS and have them supply it to Comet.
        deal(USDS, user, 10_000e18);
        vm.startPrank(user);
        IERC20(USDS).approve(COMET, type(uint256).max);
        ICometExt(COMET).supply(USDS, 10_000e18);
        // Protocol-layer delegation: boolean, unbounded — the exact primitive
        // Permit3 is supposed to be the amount gate for.
        ICometExt(COMET).allow(address(module), true);
        // Permit3 per-order cap: 500 USDS for this (comet, asset), scoped
        // to a specific spender (e.g. the settlement contract).
        permit3.approveTaker(spender, address(module), ref, 500e18, 0);
        vm.stopPrank();
    }

    function test_withdraw_throughPermit3() public {
        uint256 receiverBalBefore = IERC20(USDS).balanceOf(receiver);

        vm.prank(spender);
        permit3.take(address(module), user, 500e18, receiver, data);

        // USDS landed with the receiver (Comet can return 1 wei less due to
        // index rounding — tolerate a 1-wei delta).
        uint256 got = IERC20(USDS).balanceOf(receiver) - receiverBalBefore;
        assertApproxEqAbs(got, 500e18, 1, "receiver didn't get USDS");

        (uint160 amt,,) = permit3.takerAllowance(user, spender, address(module), ref);
        assertEq(amt, 0, "allowance not decremented");
    }

    function test_withdraw_revertsWithoutAllowance() public {
        // Different asset in data — different ref, zero allowance.
        bytes memory otherData = abi.encode(COMET, address(0xDEAD));

        vm.prank(spender);
        vm.expectRevert(abi.encodeWithSelector(IPermit3.InsufficientAllowance.selector, uint160(0)));
        permit3.take(address(module), user, 1, receiver, otherData);
    }

    /// @dev An unapproved caller hits a zero allowance on
    ///      (user, caller, module, ref) and is rejected before Comet.
    function test_withdraw_revertsForUnapprovedSpender() public {
        address intruder = makeAddr("intruder");
        vm.prank(intruder);
        vm.expectRevert(abi.encodeWithSelector(IPermit3.InsufficientAllowance.selector, uint160(0)));
        permit3.take(address(module), user, 1, receiver, data);
    }
}
