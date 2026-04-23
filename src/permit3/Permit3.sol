// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {IPermit3} from "../interfaces/IPermit3.sol";
import {ITakerModule} from "../interfaces/ITakerModule.sol";

/// @title Permit3
/// @notice Unified allowance hub for ERC20 transfers *and* protocol taker ops
///         (borrow, withdraw, unstake, claim, …).
///
///  Design
///  ──────
///  Permit3 holds two allowance books, both keyed on an explicit spender:
///
///    • token book — keyed (user → spender → token). A spender calls
///      `transferFrom(user, to, token, amount)`; Permit3 decrements the
///      spender's allowance and calls the token's ERC20 transferFrom.
///      Permit2-equivalent.
///
///    • taker book — keyed (user → spender → module → bytes32 ref). The
///      approved `spender` (typically a settlement contract) invokes
///      `take(module, user, amount, receiver, data)`; Permit3 computes
///      `ref = keccak256(data)`, decrements the allowance on
///      (user, msg.sender, module, ref), then invokes the module's
///      `takeOnBehalf`. Any caller whose msg.sender does not match the
///      approved spender slot has a zero allowance and cannot dispatch.
///
///  Permit3 knows nothing about lending/staking/vault protocols. Protocol
///  heterogeneity stays in modules. Single-operation modules keep blast
///  radius small: approvals on a borrow module cannot be used to withdraw,
///  and vice versa.
///
///  Both on-chain `approveX` flows and EIP-712 signed permits are
///  supported. Signed permits may bind an arbitrary witness (e.g. an order
///  hash) via `permitBatchWithWitness`, so a single signature can cover
///  both a batch of allowances and the order that will consume them.
///
///  Signatures accept 65-byte `(r,s,v)`, 64-byte EIP-2098 compact, and
///  EIP-1271 smart-account signatures. ECDSA is low-s enforced.
contract Permit3 is IPermit3 {
    /// @dev user → spender → token → (amount, expiration, nonce)
    mapping(address => mapping(address => mapping(address => PackedAllowance))) private _tokenAllowance;

    /// @dev user → spender → module → ref → (amount, expiration, nonce).
    ///      `spender` is the address permitted to invoke `take`. `ref` is
    ///      opaque to Permit3 — a module-specific position key (Morpho
    ///      marketId, Comet address, Aave (asset, rateMode), LST
    ///      withdrawal NFT id, …).
    mapping(address => mapping(address => mapping(address => mapping(bytes32 => PackedAllowance)))) private
        _takerAllowance;

    /// @notice EIP-712 domain separator for signed permits.
    bytes32 public immutable override DOMAIN_SEPARATOR;

    uint256 private _locked = 1;

    // ──────────────────── EIP-712 typehashes ────────────────────

    bytes32 private constant _TOKEN_PERMIT_TYPEHASH =
        keccak256("TokenPermit(address spender,address token,uint160 amount,uint48 expiration,uint48 nonce)");

    bytes32 private constant _TAKER_PERMIT_TYPEHASH = keccak256(
        "TakerPermit(address spender,address module,bytes32 ref,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    bytes32 private constant _PERMIT_BATCH_TYPEHASH = keccak256(
        "PermitBatch(TokenPermit[] tokens,TakerPermit[] takers,uint256 deadline)"
        "TakerPermit(address spender,address module,bytes32 ref,uint160 amount,uint48 expiration,uint48 nonce)"
        "TokenPermit(address spender,address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    /// @dev Type-string stub for the witness-bound batch. The caller appends
    ///      its own `"<fieldName> <WitnessType>)<TYPES IN ALPHABETICAL ORDER>"`.
    string private constant _PERMIT_BATCH_WITNESS_STUB =
        "PermitBatchWitness(TokenPermit[] tokens,TakerPermit[] takers,uint256 deadline,";

    // ──────────────────── Signature constants ────────────────────

    /// @dev secp256k1 curve order / 2. `s` above this is malleable.
    uint256 private constant _SECP256K1_HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @dev EIP-1271 magic return value for a valid signature.
    bytes4 private constant _ERC1271_MAGIC_VALUE = 0x1626ba7e;

    /// @dev Bump cap for `invalidate*Nonces` (matches Permit2).
    uint48 private constant _MAX_NONCE_INCREMENT = type(uint16).max;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Permit3"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    modifier nonReentrant() {
        if (_locked != 1) revert Reentrancy();
        _locked = 2;
        _;
        _locked = 1;
    }

    // ──────────────────── Token side ────────────────────

    function approveToken(address spender, address token, uint160 amount, uint48 expiration) external override {
        PackedAllowance storage a = _tokenAllowance[msg.sender][spender][token];
        a.amount = amount;
        a.expiration = expiration;
        emit TokenApproval(msg.sender, spender, token, amount, expiration);
    }

    function transferFrom(address user, address to, address token, uint160 amount) external override {
        PackedAllowance storage a = _tokenAllowance[user][msg.sender][token];
        _spend(a, amount);
        IERC20(token).transferFrom(user, to, amount);
    }

    function tokenAllowance(address user, address spender, address token)
        external
        view
        override
        returns (uint160 amount, uint48 expiration, uint48 nonce)
    {
        PackedAllowance storage a = _tokenAllowance[user][spender][token];
        return (a.amount, a.expiration, a.nonce);
    }

    // ──────────────────── Taker side ────────────────────

    function approveTaker(address spender, address module, bytes32 ref, uint160 amount, uint48 expiration)
        external
        override
    {
        PackedAllowance storage a = _takerAllowance[msg.sender][spender][module][ref];
        a.amount = amount;
        a.expiration = expiration;
        emit TakerApproval(msg.sender, spender, module, ref, amount, expiration);
    }

    function take(address module, address user, uint160 amount, address receiver, bytes calldata data)
        external
        override
        nonReentrant
    {
        bytes32 ref = keccak256(data);
        _spend(_takerAllowance[user][msg.sender][module][ref], amount);
        ITakerModule(module).takeOnBehalf(user, amount, receiver, data);
    }

    function takerAllowance(address user, address spender, address module, bytes32 ref)
        external
        view
        override
        returns (uint160 amount, uint48 expiration, uint48 nonce)
    {
        PackedAllowance storage a = _takerAllowance[user][spender][module][ref];
        return (a.amount, a.expiration, a.nonce);
    }

    // ──────────────────── Revocation ────────────────────

    function revokeToken(address spender, address token) external override {
        PackedAllowance storage a = _tokenAllowance[msg.sender][spender][token];
        a.amount = 0;
        a.expiration = 0;
        emit TokenApproval(msg.sender, spender, token, 0, 0);
    }

    function revokeTaker(address spender, address module, bytes32 ref) external override {
        PackedAllowance storage a = _takerAllowance[msg.sender][spender][module][ref];
        a.amount = 0;
        a.expiration = 0;
        emit TakerApproval(msg.sender, spender, module, ref, 0, 0);
    }

    function lockdown(address spender) external override {
        // Intent-only signal; callers sweep specific (token, ref) pairs via
        // revokeToken / revokeTaker using their off-chain-indexed list.
        emit Lockdown(msg.sender, spender);
    }

    // ──────────────────── Nonce invalidation ────────────────────

    function invalidateTokenNonces(address spender, address token, uint48 newNonce) external override {
        PackedAllowance storage a = _tokenAllowance[msg.sender][spender][token];
        uint48 old = a.nonce;
        if (newNonce <= old) revert InvalidPermitNonce();
        unchecked {
            if (newNonce - old > _MAX_NONCE_INCREMENT) revert ExcessiveInvalidation();
        }
        a.nonce = newNonce;
        emit TokenNonceInvalidation(msg.sender, spender, token, newNonce, old);
    }

    function invalidateTakerNonces(address spender, address module, bytes32 ref, uint48 newNonce) external override {
        PackedAllowance storage a = _takerAllowance[msg.sender][spender][module][ref];
        uint48 old = a.nonce;
        if (newNonce <= old) revert InvalidPermitNonce();
        unchecked {
            if (newNonce - old > _MAX_NONCE_INCREMENT) revert ExcessiveInvalidation();
        }
        a.nonce = newNonce;
        emit TakerNonceInvalidation(msg.sender, spender, module, ref, newNonce, old);
    }

    // ──────────────────── Signed permits ────────────────────

    function permitBatch(address owner, PermitBatch calldata batch, bytes calldata sig) external override {
        if (block.timestamp > batch.deadline) revert PermitExpired();
        bytes32 hashStruct = keccak256(
            abi.encode(
                _PERMIT_BATCH_TYPEHASH,
                _hashTokenPermits(batch.tokens),
                _hashTakerPermits(batch.takers),
                batch.deadline
            )
        );
        _verifyPermitSig(owner, hashStruct, sig);
        _applyBatch(owner, batch);
    }

    function permitBatchWithWitness(
        address owner,
        PermitBatch calldata batch,
        bytes32 witness,
        string calldata witnessTypeString,
        bytes calldata sig
    ) external override {
        if (block.timestamp > batch.deadline) revert PermitExpired();
        bytes32 typeHash = keccak256(abi.encodePacked(_PERMIT_BATCH_WITNESS_STUB, witnessTypeString));
        bytes32 hashStruct = keccak256(
            abi.encode(
                typeHash,
                _hashTokenPermits(batch.tokens),
                _hashTakerPermits(batch.takers),
                batch.deadline,
                witness
            )
        );
        _verifyPermitSig(owner, hashStruct, sig);
        _applyBatch(owner, batch);
    }

    // ──────────────────── Permit internals ────────────────────

    function _hashTokenPermits(TokenPermit[] calldata permits) private pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](permits.length);
        for (uint256 i; i < permits.length; i++) {
            hashes[i] = keccak256(
                abi.encode(
                    _TOKEN_PERMIT_TYPEHASH,
                    permits[i].spender,
                    permits[i].token,
                    permits[i].amount,
                    permits[i].expiration,
                    permits[i].nonce
                )
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function _hashTakerPermits(TakerPermit[] calldata permits) private pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](permits.length);
        for (uint256 i; i < permits.length; i++) {
            hashes[i] = keccak256(
                abi.encode(
                    _TAKER_PERMIT_TYPEHASH,
                    permits[i].spender,
                    permits[i].module,
                    permits[i].ref,
                    permits[i].amount,
                    permits[i].expiration,
                    permits[i].nonce
                )
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

    /// @dev Verify `sig` over the EIP-712 digest of `hashStruct`.
    ///      Supports 65-byte `(r,s,v)`, 64-byte EIP-2098 compact, and
    ///      EIP-1271 smart-account signatures. ECDSA is low-s only.
    function _verifyPermitSig(address owner, bytes32 hashStruct, bytes calldata sig) private view {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        if (owner.code.length == 0) {
            // EOA: recover via ecrecover with malleability guard.
            bytes32 r;
            bytes32 s;
            uint8 v;

            if (sig.length == 65) {
                r = bytes32(sig[0:32]);
                s = bytes32(sig[32:64]);
                v = uint8(sig[64]);
            } else if (sig.length == 64) {
                // EIP-2098 compact: (r, vs) where vs = (v-27) << 255 | s
                r = bytes32(sig[0:32]);
                bytes32 vs = bytes32(sig[32:64]);
                s = vs & bytes32(uint256(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff));
                v = 27 + uint8(uint256(vs) >> 255);
            } else {
                revert InvalidPermitSignature();
            }

            if (uint256(s) > _SECP256K1_HALF_N) revert InvalidPermitSignature();
            if (v != 27 && v != 28) revert InvalidPermitSignature();

            address recovered = ecrecover(digest, v, r, s);
            if (recovered == address(0) || recovered != owner) revert InvalidPermitSignature();
        } else {
            // Contract: EIP-1271 fallback.
            (bool ok, bytes memory ret) =
                owner.staticcall(abi.encodeWithSelector(_ERC1271_MAGIC_VALUE, digest, sig));
            if (!ok || ret.length < 32) revert InvalidPermitSignature();
            if (abi.decode(ret, (bytes4)) != _ERC1271_MAGIC_VALUE) revert InvalidPermitSignature();
        }
    }

    function _applyBatch(address owner, PermitBatch calldata batch) private {
        for (uint256 i; i < batch.tokens.length; i++) {
            TokenPermit calldata p = batch.tokens[i];
            PackedAllowance storage a = _tokenAllowance[owner][p.spender][p.token];
            if (p.nonce != a.nonce) revert InvalidPermitNonce();
            a.amount = p.amount;
            a.expiration = p.expiration;
            unchecked {
                a.nonce = p.nonce + 1;
            }
            emit TokenApproval(owner, p.spender, p.token, p.amount, p.expiration);
        }
        for (uint256 i; i < batch.takers.length; i++) {
            TakerPermit calldata p = batch.takers[i];
            PackedAllowance storage a = _takerAllowance[owner][p.spender][p.module][p.ref];
            if (p.nonce != a.nonce) revert InvalidPermitNonce();
            a.amount = p.amount;
            a.expiration = p.expiration;
            unchecked {
                a.nonce = p.nonce + 1;
            }
            emit TakerApproval(owner, p.spender, p.module, p.ref, p.amount, p.expiration);
        }
    }

    // ──────────────────── Internal ────────────────────

    function _spend(PackedAllowance storage a, uint160 amount) private {
        uint48 exp = a.expiration;
        // expiration == 0 means "no expiration" — matches Permit2 ergonomics
        if (exp != 0 && block.timestamp > exp) revert AllowanceExpired(exp);

        uint160 cur = a.amount;
        // type(uint160).max == "infinite, do not decrement"
        if (cur != type(uint160).max) {
            if (cur < amount) revert InsufficientAllowance(cur);
            unchecked {
                a.amount = cur - amount;
            }
        }
    }
}
