// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Permit3Test} from "./base/Permit3Test.sol";
import {IPermit3} from "../src/interfaces/IPermit3.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockTakerModule, ReentrantTakerModule, PullingTakerModule} from "./mocks/MockTakerModule.sol";

/// @notice Permit3-specific tests for the taker book — the surface that does
///         not exist in Permit2. Covers approveTaker/take/revokeTaker, ref =
///         keccak256(data) dispatch, reentrancy, and invalidateTakerNonces.
contract TakerBookTest is Permit3Test {
    event TakerApproval(
        address indexed user, address indexed module, bytes32 indexed ref, uint160 amount, uint48 expiration
    );
    event TakerNonceInvalidation(
        address indexed user, address indexed module, bytes32 indexed ref, uint48 newNonce, uint48 oldNonce
    );

    MockERC20 internal borrowToken;
    MockTakerModule internal module;

    address internal constant RECEIVER = address(0xBEEF);

    function setUp() public {
        _baseSetup();
        borrowToken = new MockERC20();
        module = new MockTakerModule(address(permit3), address(borrowToken));
    }

    // ──────────────────── approveTaker / view ────────────────────

    function testApproveTakerSetsAllowance() public {
        bytes memory data = abi.encode(uint256(0xCAFE));
        bytes32 ref = keccak256(data);

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit TakerApproval(alice, address(module), ref, DEFAULT_AMOUNT, defaultExpiration);
        permit3.approveTaker(address(module), ref, DEFAULT_AMOUNT, defaultExpiration);

        (uint160 amount, uint48 expiration, uint48 nonce) = permit3.takerAllowance(alice, address(module), ref);
        assertEq(amount, DEFAULT_AMOUNT);
        assertEq(expiration, defaultExpiration);
        assertEq(nonce, 0);
    }

    // ──────────────────── take ────────────────────

    function testTakeDispatchesWithRefFromData() public {
        bytes memory data = abi.encode(address(0xAA), address(0xBB));
        bytes32 ref = keccak256(data);

        vm.prank(alice);
        permit3.approveTaker(address(module), ref, DEFAULT_AMOUNT, defaultExpiration);

        permit3.take(address(module), alice, 0.4e18, RECEIVER, data);

        assertEq(module.callCount(), 1);
        assertEq(module.lastOnBehalfOf(), alice);
        assertEq(module.lastAmount(), 0.4e18);
        assertEq(module.lastReceiver(), RECEIVER);
        assertEq(keccak256(module.lastData()), keccak256(data));
        assertEq(borrowToken.balanceOf(RECEIVER), 0.4e18);
    }

    function testTakeDecrementsAllowance() public {
        bytes memory data = abi.encode(uint256(1));
        bytes32 ref = keccak256(data);
        vm.prank(alice);
        permit3.approveTaker(address(module), ref, 1e18, defaultExpiration);

        permit3.take(address(module), alice, 0.3e18, RECEIVER, data);

        (uint160 amount,,) = permit3.takerAllowance(alice, address(module), ref);
        assertEq(amount, 1e18 - 0.3e18);
    }

    /// @dev Any change to `data` changes the ref, so the other ref's
    ///      allowance does not apply — revert with `InsufficientAllowance(0)`.
    function testTakeWithDifferentDataUsesDifferentRef() public {
        bytes memory dataA = abi.encode(uint256(1));
        bytes memory dataB = abi.encode(uint256(2));
        vm.prank(alice);
        permit3.approveTaker(address(module), keccak256(dataA), 1e18, defaultExpiration);

        vm.expectRevert(abi.encodeWithSelector(IPermit3.InsufficientAllowance.selector, uint160(0)));
        permit3.take(address(module), alice, 1, RECEIVER, dataB);
    }

    function testTakeExpiredReverts() public {
        bytes memory data = hex"aabb";
        bytes32 ref = keccak256(data);
        vm.prank(alice);
        permit3.approveTaker(address(module), ref, 1e18, defaultExpiration);

        vm.warp(uint256(defaultExpiration) + 1);

        vm.expectRevert(abi.encodeWithSelector(IPermit3.AllowanceExpired.selector, defaultExpiration));
        permit3.take(address(module), alice, 1, RECEIVER, data);
    }

    function testTakeInsufficientAllowanceReverts() public {
        bytes memory data = hex"bb";
        vm.prank(alice);
        permit3.approveTaker(address(module), keccak256(data), 1e18, defaultExpiration);

        vm.expectRevert(abi.encodeWithSelector(IPermit3.InsufficientAllowance.selector, uint160(1e18)));
        permit3.take(address(module), alice, 1e18 + 1, RECEIVER, data);
    }

    function testTakeMaxAllowanceNotDecremented() public {
        bytes memory data = hex"cc";
        bytes32 ref = keccak256(data);
        vm.prank(alice);
        permit3.approveTaker(address(module), ref, type(uint160).max, 0);

        permit3.take(address(module), alice, 1e18, RECEIVER, data);
        permit3.take(address(module), alice, 2e18, RECEIVER, data);

        (uint160 amount,,) = permit3.takerAllowance(alice, address(module), ref);
        assertEq(amount, type(uint160).max);
    }

    /// @dev Permit3.take is `nonReentrant`; a module that tries to re-enter
    ///      take() must revert.
    function testTakeRejectsReentrancy() public {
        ReentrantTakerModule reentrant = new ReentrantTakerModule(address(permit3));
        bytes memory data = hex"dd";
        bytes32 ref = keccak256(data);
        vm.prank(alice);
        permit3.approveTaker(address(reentrant), ref, type(uint160).max, 0);

        vm.expectRevert(IPermit3.Reentrancy.selector);
        permit3.take(address(reentrant), alice, 1, RECEIVER, data);
    }

    /// @dev A module invoking `permit3.transferFrom` mid-take pulls from the
    ///      user's token allowance, exercising the combined token + taker
    ///      flow and proving the two books are independent.
    function testModuleCanPullErc20InsideTake() public {
        PullingTakerModule pulling = new PullingTakerModule(address(permit3));

        bytes memory data = abi.encode(address(token0));
        bytes32 ref = keccak256(data);

        vm.startPrank(alice);
        permit3.approveTaker(address(pulling), ref, 1e18, defaultExpiration);
        permit3.approveToken(address(pulling), address(token0), 1e18, defaultExpiration);
        vm.stopPrank();

        uint256 before = token0.balanceOf(RECEIVER);
        permit3.take(address(pulling), alice, 0.5e18, RECEIVER, data);
        assertEq(token0.balanceOf(RECEIVER), before + 0.5e18);

        // Both books are decremented independently.
        (uint160 takerAmt,,) = permit3.takerAllowance(alice, address(pulling), ref);
        (uint160 tokenAmt,,) = permit3.tokenAllowance(alice, address(pulling), address(token0));
        assertEq(takerAmt, 0.5e18);
        assertEq(tokenAmt, 0.5e18);
    }

    // ──────────────────── revokeTaker ────────────────────

    function testRevokeTakerZeroesAllowance() public {
        bytes32 ref = keccak256(hex"01");
        vm.prank(alice);
        permit3.approveTaker(address(module), ref, 1e18, defaultExpiration);

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit TakerApproval(alice, address(module), ref, 0, 0);
        permit3.revokeTaker(address(module), ref);

        (uint160 amount, uint48 expiration,) = permit3.takerAllowance(alice, address(module), ref);
        assertEq(amount, 0);
        assertEq(expiration, 0);
    }

    function testRevokeTakerPreservesNonce() public {
        bytes32 ref = keccak256(hex"02");
        vm.startPrank(alice);
        permit3.invalidateTakerNonces(address(module), ref, 4);
        permit3.approveTaker(address(module), ref, 1e18, defaultExpiration);
        permit3.revokeTaker(address(module), ref);
        vm.stopPrank();

        (,, uint48 nonce) = permit3.takerAllowance(alice, address(module), ref);
        assertEq(nonce, 4);
    }

    // ──────────────────── invalidateTakerNonces ────────────────────

    function testInvalidateTakerNoncesAdvances() public {
        bytes32 ref = keccak256(hex"03");
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit TakerNonceInvalidation(alice, address(module), ref, 3, 0);
        permit3.invalidateTakerNonces(address(module), ref, 3);

        (,, uint48 nonce) = permit3.takerAllowance(alice, address(module), ref);
        assertEq(nonce, 3);
    }

    function testInvalidateTakerNoncesMustBeForward() public {
        bytes32 ref = keccak256(hex"04");
        vm.prank(alice);
        permit3.invalidateTakerNonces(address(module), ref, 2);

        vm.prank(alice);
        vm.expectRevert(IPermit3.InvalidPermitNonce.selector);
        permit3.invalidateTakerNonces(address(module), ref, 2);
    }

    function testInvalidateTakerNoncesExcessiveReverts() public {
        bytes32 ref = keccak256(hex"05");
        vm.prank(alice);
        vm.expectRevert(IPermit3.ExcessiveInvalidation.selector);
        permit3.invalidateTakerNonces(address(module), ref, uint48(type(uint16).max) + 1);
    }
}
