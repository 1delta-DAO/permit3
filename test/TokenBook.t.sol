// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Permit3Test} from "./base/Permit3Test.sol";
import {IPermit3} from "../src/interfaces/IPermit3.sol";

/// @notice Direct on-chain token-book flows: approve, transferFrom, revoke,
///         lockdown, invalidateTokenNonces. Mirrors `testApprove` /
///         `testInvalidate*` / `testLockdown*` in
///         `permit2/test/AllowanceTransferTest.t.sol`.
contract TokenBookTest is Permit3Test {
    event TokenApproval(
        address indexed user, address indexed spender, address indexed token, uint160 amount, uint48 expiration
    );
    event TokenNonceInvalidation(
        address indexed user, address indexed spender, address indexed token, uint48 newNonce, uint48 oldNonce
    );
    event Lockdown(address indexed user, address spender);

    address internal constant RECIPIENT = address(0xBEEF);

    function setUp() public {
        _baseSetup();
    }

    // ──────────────────── approveToken ────────────────────

    function testApproveTokenSetsAllowance() public {
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit TokenApproval(alice, bob, address(token0), DEFAULT_AMOUNT, defaultExpiration);
        permit3.approveToken(bob, address(token0), DEFAULT_AMOUNT, defaultExpiration);

        (uint160 amount, uint48 expiration, uint48 nonce) = permit3.tokenAllowance(alice, bob, address(token0));
        assertEq(amount, DEFAULT_AMOUNT);
        assertEq(expiration, defaultExpiration);
        assertEq(nonce, 0);
    }

    function testApproveTokenOverwrites() public {
        vm.startPrank(alice);
        permit3.approveToken(bob, address(token0), 1e18, defaultExpiration);
        permit3.approveToken(bob, address(token0), 5e18, defaultExpiration + 1);
        vm.stopPrank();

        (uint160 amount, uint48 expiration,) = permit3.tokenAllowance(alice, bob, address(token0));
        assertEq(amount, 5e18);
        assertEq(expiration, defaultExpiration + 1);
    }

    // ──────────────────── transferFrom ────────────────────

    function testTransferFromDecrementsAllowance() public {
        vm.prank(alice);
        permit3.approveToken(bob, address(token0), DEFAULT_AMOUNT, defaultExpiration);

        uint256 before = token0.balanceOf(RECIPIENT);

        vm.prank(bob);
        permit3.transferFrom(alice, RECIPIENT, address(token0), 0.25e18);

        assertEq(token0.balanceOf(RECIPIENT), before + 0.25e18);
        (uint160 amount,,) = permit3.tokenAllowance(alice, bob, address(token0));
        assertEq(amount, DEFAULT_AMOUNT - 0.25e18);
    }

    function testTransferFromInsufficientAllowanceReverts() public {
        vm.prank(alice);
        permit3.approveToken(bob, address(token0), 1e18, defaultExpiration);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IPermit3.InsufficientAllowance.selector, uint160(1e18)));
        permit3.transferFrom(alice, RECIPIENT, address(token0), 1e18 + 1);
    }

    function testTransferFromExpiredReverts() public {
        vm.prank(alice);
        permit3.approveToken(bob, address(token0), DEFAULT_AMOUNT, defaultExpiration);

        vm.warp(uint256(defaultExpiration) + 1);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IPermit3.AllowanceExpired.selector, defaultExpiration));
        permit3.transferFrom(alice, RECIPIENT, address(token0), 1);
    }

    function testTransferFromZeroExpirationNeverExpires() public {
        vm.prank(alice);
        permit3.approveToken(bob, address(token0), DEFAULT_AMOUNT, 0);

        vm.warp(block.timestamp + 365 days);

        vm.prank(bob);
        permit3.transferFrom(alice, RECIPIENT, address(token0), 1e18);
        assertEq(token0.balanceOf(RECIPIENT), 1e18);
    }

    function testMaxAllowanceNotDecremented() public {
        vm.prank(alice);
        permit3.approveToken(bob, address(token0), type(uint160).max, defaultExpiration);

        vm.prank(bob);
        permit3.transferFrom(alice, RECIPIENT, address(token0), 1e18);

        (uint160 amount,,) = permit3.tokenAllowance(alice, bob, address(token0));
        assertEq(amount, type(uint160).max);
    }

    // ──────────────────── revokeToken ────────────────────

    function testRevokeTokenZeroesAllowance() public {
        vm.prank(alice);
        permit3.approveToken(bob, address(token0), DEFAULT_AMOUNT, defaultExpiration);

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit TokenApproval(alice, bob, address(token0), 0, 0);
        permit3.revokeToken(bob, address(token0));

        (uint160 amount, uint48 expiration,) = permit3.tokenAllowance(alice, bob, address(token0));
        assertEq(amount, 0);
        assertEq(expiration, 0);
    }

    /// @dev Revoking must NOT reset the per-slot nonce: doing so would open
    ///      a replay window on any previously-invalidated signed permit.
    function testRevokeTokenPreservesNonce() public {
        vm.prank(alice);
        permit3.invalidateTokenNonces(bob, address(token0), 7);
        (,, uint48 nonce) = permit3.tokenAllowance(alice, bob, address(token0));
        assertEq(nonce, 7);

        vm.prank(alice);
        permit3.approveToken(bob, address(token0), DEFAULT_AMOUNT, defaultExpiration);
        vm.prank(alice);
        permit3.revokeToken(bob, address(token0));

        (,, uint48 nonceAfter) = permit3.tokenAllowance(alice, bob, address(token0));
        assertEq(nonceAfter, 7, "nonce must be preserved across revoke/reapprove");
    }

    // ──────────────────── lockdown ────────────────────

    function testLockdownEmitsEvent() public {
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Lockdown(alice, bob);
        permit3.lockdown(bob);
    }

    // ──────────────────── invalidateTokenNonces ────────────────────

    function testInvalidateTokenNoncesAdvances() public {
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit TokenNonceInvalidation(alice, bob, address(token0), 5, 0);
        permit3.invalidateTokenNonces(bob, address(token0), 5);

        (,, uint48 nonce) = permit3.tokenAllowance(alice, bob, address(token0));
        assertEq(nonce, 5);
    }

    function testInvalidateTokenNoncesMustBeForward() public {
        vm.prank(alice);
        permit3.invalidateTokenNonces(bob, address(token0), 5);

        vm.prank(alice);
        vm.expectRevert(IPermit3.InvalidPermitNonce.selector);
        permit3.invalidateTokenNonces(bob, address(token0), 5);

        vm.prank(alice);
        vm.expectRevert(IPermit3.InvalidPermitNonce.selector);
        permit3.invalidateTokenNonces(bob, address(token0), 3);
    }

    function testInvalidateTokenNoncesExcessiveReverts() public {
        uint48 tooFar = uint48(type(uint16).max) + 1;
        vm.prank(alice);
        vm.expectRevert(IPermit3.ExcessiveInvalidation.selector);
        permit3.invalidateTokenNonces(bob, address(token0), tooFar);
    }

    function testInvalidateTokenNoncesExactlyMaxBumpWorks() public {
        uint48 atCap = uint48(type(uint16).max);
        vm.prank(alice);
        permit3.invalidateTokenNonces(bob, address(token0), atCap);
        (,, uint48 nonce) = permit3.tokenAllowance(alice, bob, address(token0));
        assertEq(nonce, atCap);
    }
}
