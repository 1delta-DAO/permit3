// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";

import {Permit3} from "../src/permit3/Permit3.sol";
import {IPermit3} from "../src/interfaces/IPermit3.sol";
import {MarketParams, MorphoBlueBorrowModule} from "../src/modules/MorphoBlueBorrowModule.sol";

/// Extended Morpho Blue interface needed for the test setup (supply
/// collateral and authorise the borrow module).
interface IMorphoExt {
    function setAuthorization(address authorized, bool newIsAuthorized) external;
    function supplyCollateral(MarketParams memory marketParams, uint256 assets, address onBehalf, bytes calldata data)
        external;
}

/// @notice Fork test: MorphoBlueBorrowModule actually borrows on a live
///         Morpho Blue market, gated only by the Permit3 taker allowance.
///
///         Uses the wstETH/USDC 86% market on mainnet Morpho Blue.
///
///         Happy path:
///           1. User supplies wstETH collateral directly to Morpho.
///           2. User authorises the module on Morpho (boolean, unbounded).
///           3. User approves Permit3 with a 1_000 USDC cap on the borrow ref.
///           4. A random caller invokes `permit3.take(...)` with matching data.
///           5. The module borrows 1_000 USDC and sends it to the receiver.
///
///         Negative path:
///           `take` with amount > approved cap reverts on the Permit3
///           allowance gate, never reaching the module / Morpho.
contract MorphoBlueBorrowModuleForkTest is Test {
    // Mainnet Morpho Blue.
    address constant MORPHO = 0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WSTETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;

    // Live wstETH/USDC 86% market params (discovered via CreateMarket event
    // at block 18925910). `keccak256(abi.encode(MarketParams))` for these
    // fields equals marketId 0xb323495f7e4148be5643a4ea4a8221eef163e4bccfdedc2a6f4696baacbc86cc.
    address constant ORACLE = 0x48F7E36EB6B826B2dF4B2E630B62Cd25e89E40e2;
    address constant IRM = 0x870aC11D48B15DB9a138Cf899d20F13F79Ba00BC;
    uint256 constant LLTV = 0.86e18;

    Permit3 permit3;
    MorphoBlueBorrowModule module;

    address user = makeAddr("user");
    address spender = makeAddr("spender");
    address receiver = makeAddr("receiver");

    MarketParams marketParams;
    bytes data;
    bytes32 ref;

    function setUp() public {
        vm.createSelectFork(vm.envOr("MAINNET_RPC_URL", string("https://ethereum-rpc.publicnode.com")));

        permit3 = new Permit3();
        module = new MorphoBlueBorrowModule(MORPHO, address(permit3));

        marketParams = MarketParams({
            loanToken: USDC,
            collateralToken: WSTETH,
            oracle: ORACLE,
            irm: IRM,
            lltv: LLTV
        });
        data = abi.encode(marketParams);
        ref = keccak256(data);

        // Give the user 10 wstETH and supply 5 of it as collateral — plenty
        // to back a 1_000 USDC borrow at 86% LLTV even at a $1000 wstETH price.
        deal(WSTETH, user, 10 ether);
        vm.startPrank(user);
        IERC20(WSTETH).approve(MORPHO, type(uint256).max);
        IMorphoExt(MORPHO).supplyCollateral(marketParams, 5 ether, user, "");
        // Protocol-layer delegation — boolean, unbounded: exactly the thing
        // Permit3 is meant to be the amount gate for.
        IMorphoExt(MORPHO).setAuthorization(address(module), true);
        // Permit3 per-order cap: 1_000 USDC for this specific market, scoped
        // to a specific spender (e.g. the settlement contract).
        permit3.approveTaker(spender, address(module), ref, 1_000e6, 0);
        vm.stopPrank();
    }

    function test_borrow_throughPermit3() public {
        uint256 receiverBalBefore = IERC20(USDC).balanceOf(receiver);

        vm.prank(spender);
        permit3.take(address(module), user, 1_000e6, receiver, data);

        assertEq(IERC20(USDC).balanceOf(receiver) - receiverBalBefore, 1_000e6, "receiver didn't get USDC");

        (uint160 amt,,) = permit3.takerAllowance(user, spender, address(module), ref);
        assertEq(amt, 0, "allowance not decremented");
    }

    function test_borrow_revertsOverCap() public {
        vm.prank(spender);
        vm.expectRevert(abi.encodeWithSelector(IPermit3.InsufficientAllowance.selector, uint160(1_000e6)));
        permit3.take(address(module), user, 1_000e6 + 1, receiver, data);
    }

    /// @dev An unapproved caller hits the zero allowance on
    ///      (user, caller, module, ref) and is rejected before Morpho.
    function test_borrow_revertsForUnapprovedSpender() public {
        address intruder = makeAddr("intruder");
        vm.prank(intruder);
        vm.expectRevert(abi.encodeWithSelector(IPermit3.InsufficientAllowance.selector, uint160(0)));
        permit3.take(address(module), user, 1, receiver, data);
    }
}
