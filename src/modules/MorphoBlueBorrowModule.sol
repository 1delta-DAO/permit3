// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ITakerModule} from "../interfaces/ITakerModule.sol";

/// @notice Morpho Blue market identifier. `keccak256(abi.encode(MarketParams))`
///         is the canonical Morpho `marketId`.
struct MarketParams {
    address loanToken;
    address collateralToken;
    address oracle;
    address irm;
    uint256 lltv;
}

interface IMorpho {
    function borrow(
        MarketParams memory marketParams,
        uint256 assets,
        uint256 shares,
        address onBehalf,
        address receiver
    ) external returns (uint256 assetsBorrowed, uint256 sharesBorrowed);
}

/// @title MorphoBlueBorrowModule
/// @notice Single-op taker module: borrow the loan token of a Morpho Blue
///         market on behalf of `onBehalfOf`, routed to `receiver`.
///
/// `data` layout:
///   abi.encode(MarketParams)
///
/// `ref = keccak256(data)` therefore coincides with the Morpho marketId,
/// so an approval against one market cannot be replayed against another.
///
/// Why this module is a useful example
/// ───────────────────────────────────
/// Morpho's native delegation is boolean:
///
///   morpho.setAuthorization(module, true)
///
/// grants unbounded borrow capacity against every market the user has
/// collateral in, for as long as the flag is set. There is no
/// protocol-layer amount cap — Permit3 is the only amount gate.
/// `approveTaker(MorphoBlueBorrowModule, keccak256(MarketParams), cap, expiry)`
/// caps borrows to `cap` for exactly this market and nothing else.
contract MorphoBlueBorrowModule is ITakerModule {
    IMorpho public immutable MORPHO;
    address public immutable PERMIT3;

    error NotPermit3();

    constructor(address morpho, address permit3) {
        MORPHO = IMorpho(morpho);
        PERMIT3 = permit3;
    }

    /// @inheritdoc ITakerModule
    function takeOnBehalf(address onBehalfOf, uint256 amount, address receiver, bytes calldata data) external {
        if (msg.sender != PERMIT3) revert NotPermit3();
        MarketParams memory mp = abi.decode(data, (MarketParams));
        MORPHO.borrow(mp, amount, 0, onBehalfOf, receiver);
    }
}
