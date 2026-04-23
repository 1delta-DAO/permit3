// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ITakerModule} from "../interfaces/ITakerModule.sol";

interface IComet {
    function withdrawFrom(address src, address to, address asset, uint256 amount) external;
}

/// @title CometWithdrawModule
/// @notice Single-op taker module: withdraw `asset` from a Compound V3
///         (Comet) instance on behalf of `onBehalfOf`, routed to `receiver`.
///         Comet uses the same entrypoint for base-asset borrows and
///         collateral withdrawals — both are gated by this one module.
///
/// `data` layout:
///   abi.encode(address comet, address asset)
///
/// Why this module is a useful example
/// ───────────────────────────────────
/// Comet's native delegation is boolean:
///
///   comet.allow(module, true)
///
/// grants the module unbounded `withdrawFrom` capacity on the caller's
/// entire Comet position — base asset and every listed collateral — until
/// revoked. There is no protocol-layer amount cap and no per-asset cap.
/// Permit3 is the only amount- and asset-gated layer: approving this
/// module with ref `keccak256(abi.encode(comet, asset))` bounds what any
/// unprivileged caller can pull to (`comet`, `asset`, `cap`).
contract CometWithdrawModule is ITakerModule {
    address public immutable PERMIT3;

    error NotPermit3();

    constructor(address permit3) {
        PERMIT3 = permit3;
    }

    /// @inheritdoc ITakerModule
    function takeOnBehalf(address onBehalfOf, uint256 amount, address receiver, bytes calldata data) external {
        if (msg.sender != PERMIT3) revert NotPermit3();
        (address comet, address asset) = abi.decode(data, (address, address));
        IComet(comet).withdrawFrom(onBehalfOf, receiver, asset, amount);
    }
}
