// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ITakerModule} from "../interfaces/ITakerModule.sol";

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

/// @title ERC721PullModule
/// @notice Single-op taker module: pull one ERC721 from `onBehalfOf` to
///         `receiver`.
///
/// `data` layout:
///   abi.encode(address collection, uint256 tokenId)
///
/// The caller of `permit3.take` should pass `amount = 1` — ERC721
/// transfers are unit-valued and the allowance bookkeeping is just a
/// counter of how many times this ref may be pulled before needing
/// re-approval. Setting the allowance to `uint160.max` turns it into an
/// unbounded authorisation for that single tokenId (still scoped to
/// this collection and tokenId via the ref).
///
/// Why this module is a useful example
/// ───────────────────────────────────
/// ERC721 has two native approval primitives and neither composes well
/// with per-order authorisation:
///
///   - `approve(spender, tokenId)` — per-tokenId, but reset on every
///     transfer, so the user has to re-approve after each move. Not
///     useful for standing authorisations.
///   - `setApprovalForAll(operator, true)` — collection-wide and
///     infinite. An authorised operator can move any NFT the user holds
///     in that collection, at any time, for as long as the flag is set.
///
/// In practice users live with `setApprovalForAll` and accept the
/// blast radius. Routing pulls through this module lets the operator
/// flag stay on while Permit3 provides per-tokenId, per-order gating:
/// revoke one order with
/// `revokeTaker(module, keccak256(abi.encode(collection, tokenId)))`
/// without touching the collection-wide flag.
contract ERC721PullModule is ITakerModule {
    address public immutable PERMIT3;

    error NotPermit3();

    constructor(address permit3) {
        PERMIT3 = permit3;
    }

    /// @inheritdoc ITakerModule
    function takeOnBehalf(address onBehalfOf, uint256, /* amount */ address receiver, bytes calldata data) external {
        if (msg.sender != PERMIT3) revert NotPermit3();
        (address collection, uint256 tokenId) = abi.decode(data, (address, uint256));
        IERC721(collection).safeTransferFrom(onBehalfOf, receiver, tokenId);
    }
}
