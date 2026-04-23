// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IPermit3
/// @notice Dual-allowance hub:
///         • token book — Permit2-equivalent. Spender pulls ERC20 via transferFrom.
///         • taker book — Taker module pulls value from a user's position
///           (borrow, withdraw, unstake, claim, …) via Permit3.take(…).
///
///         Both books are keyed by a `spender` address. For the taker book
///         that spender is the settlement contract authorised to invoke
///         `take`; Permit3 enforces `msg.sender == spender`, so an attacker
///         cannot dispatch `take` outside the settlement's validated flow.
///
///         Users approve Permit3 once per asset/module and tune caps per order.
interface IPermit3 {
    struct PackedAllowance {
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    // ──────────────────── Permit structs (signed) ────────────────────

    struct TokenPermit {
        address spender;
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct TakerPermit {
        address spender;
        address module;
        bytes32 ref;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct PermitBatch {
        TokenPermit[] tokens;
        TakerPermit[] takers;
        uint256 deadline;
    }

    // ──────────────────── Events ────────────────────

    event TokenApproval(
        address indexed user, address indexed spender, address indexed token, uint160 amount, uint48 expiration
    );
    /// @dev `module` and `ref` identify the position; `spender` is the
    ///      only address Permit3 will accept as `msg.sender` of `take`.
    ///      Solidity allows only 3 indexed topics — we keep the three
    ///      routable keys (user, spender, module) indexed and leave `ref`
    ///      in data; consumers filter by `module` first and `ref` second.
    event TakerApproval(
        address indexed user,
        address indexed spender,
        address indexed module,
        bytes32 ref,
        uint160 amount,
        uint48 expiration
    );
    event TokenNonceInvalidation(
        address indexed user, address indexed spender, address indexed token, uint48 newNonce, uint48 oldNonce
    );
    event TakerNonceInvalidation(
        address indexed user,
        address indexed spender,
        address indexed module,
        bytes32 ref,
        uint48 newNonce,
        uint48 oldNonce
    );
    event Lockdown(address indexed user, address spender);

    // ──────────────────── Errors ────────────────────

    error AllowanceExpired(uint48 expiration);
    error InsufficientAllowance(uint160 amount);
    error Reentrancy();
    error PermitExpired();
    error InvalidPermitSignature();
    error InvalidPermitNonce();
    error ExcessiveInvalidation();

    // ──────────────────── Token side ────────────────────

    function approveToken(address spender, address token, uint160 amount, uint48 expiration) external;

    function transferFrom(address user, address to, address token, uint160 amount) external;

    function tokenAllowance(address user, address spender, address token)
        external
        view
        returns (uint160 amount, uint48 expiration, uint48 nonce);

    // ──────────────────── Taker side ────────────────────
    //
    // Keyed by `(user, spender, module, ref)` where `ref = keccak256(data)`.
    // `spender` is the address Permit3 will accept as `msg.sender` of
    // `take` — typically the settlement contract the user has chosen to
    // dispatch fills. `module` identifies the single-op adapter; `ref`
    // identifies the position.

    function approveTaker(address spender, address module, bytes32 ref, uint160 amount, uint48 expiration) external;

    /// @notice Amount-gated dispatch: requires `msg.sender` to hold the
    ///         approved spender slot, decrements the allowance on
    ///         (user, msg.sender, module, keccak256(data)), then invokes
    ///         `module.takeOnBehalf(user, amount, receiver, data)`.
    function take(address module, address user, uint160 amount, address receiver, bytes calldata data) external;

    function takerAllowance(address user, address spender, address module, bytes32 ref)
        external
        view
        returns (uint160 amount, uint48 expiration, uint48 nonce);

    // ──────────────────── Revocation ────────────────────

    function revokeToken(address spender, address token) external;

    function revokeTaker(address spender, address module, bytes32 ref) external;

    function lockdown(address spender) external;

    // ──────────────────── Signed permits ────────────────────

    function DOMAIN_SEPARATOR() external view returns (bytes32);

    /// @notice Apply a batch of signed token + taker permits in one call.
    ///         The signature is over the EIP-712 hash of `batch` under
    ///         Permit3's domain separator.
    function permitBatch(address owner, PermitBatch calldata batch, bytes calldata sig) external;

    /// @notice Same as `permitBatch` but binds the signature to an
    ///         arbitrary caller-defined `witness` (e.g. an order hash).
    ///         The same signature can never be reused for a different
    ///         witness even if `batch` and `nonce` match.
    /// @dev    `witnessTypeString` follows the Permit2 convention: the
    ///         caller provides the EIP-712 type definitions for the
    ///         witness *and* for `TokenPermit` and `TakerPermit`, in
    ///         alphabetical order, starting from `"<fieldName> <Type>)"`.
    ///         Permit3 prepends a stub of the form
    ///         `"PermitBatchWitness(TokenPermit[] tokens,TakerPermit[] takers,uint256 nonce,uint256 deadline,"`.
    function permitBatchWithWitness(
        address owner,
        PermitBatch calldata batch,
        bytes32 witness,
        string calldata witnessTypeString,
        bytes calldata sig
    ) external;

    // ──────────────────── Nonce invalidation ────────────────────

    /// @notice Advance the per-allowance nonce of `(caller, spender, token)`
    ///         to `newNonce`, invalidating any outstanding signed permit
    ///         whose `nonce` is strictly less than `newNonce`.
    /// @dev    Strictly forward-only; reverts with `InvalidPermitNonce` if
    ///         `newNonce <= oldNonce`, and with `ExcessiveInvalidation` if
    ///         the bump exceeds `type(uint16).max` in one call (griefing
    ///         bound matching Permit2).
    function invalidateTokenNonces(address spender, address token, uint48 newNonce) external;

    /// @notice Advance the per-allowance nonce of `(caller, spender, module, ref)`.
    ///         Same semantics as `invalidateTokenNonces` but for the taker
    ///         book.
    function invalidateTakerNonces(address spender, address module, bytes32 ref, uint48 newNonce) external;
}
