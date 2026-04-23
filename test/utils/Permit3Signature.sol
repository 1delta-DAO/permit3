// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {IPermit3} from "../../src/interfaces/IPermit3.sol";

/// @title Permit3Signature
/// @notice EIP-712 signing helpers for Permit3. Mirrors
///         `test/utils/PermitSignature.sol` from the upstream Permit2 suite,
///         adapted to Permit3's batch-with-per-entry-nonce layout.
contract Permit3Signature {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @dev secp256k1 curve order — used in tests to produce high-s signatures.
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes32 internal constant TOKEN_PERMIT_TYPEHASH =
        keccak256("TokenPermit(address spender,address token,uint160 amount,uint48 expiration,uint48 nonce)");

    bytes32 internal constant TAKER_PERMIT_TYPEHASH =
        keccak256("TakerPermit(address module,bytes32 ref,uint160 amount,uint48 expiration,uint48 nonce)");

    bytes32 internal constant PERMIT_BATCH_TYPEHASH = keccak256(
        "PermitBatch(TokenPermit[] tokens,TakerPermit[] takers,uint256 deadline)"
        "TakerPermit(address module,bytes32 ref,uint160 amount,uint48 expiration,uint48 nonce)"
        "TokenPermit(address spender,address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    string internal constant WITNESS_STUB =
        "PermitBatchWitness(TokenPermit[] tokens,TakerPermit[] takers,uint256 deadline,";

    // ──────────────────── Struct hashing ────────────────────

    function _hashTokens(IPermit3.TokenPermit[] memory permits) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](permits.length);
        for (uint256 i; i < permits.length; i++) {
            hashes[i] = keccak256(
                abi.encode(
                    TOKEN_PERMIT_TYPEHASH,
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

    function _hashTakers(IPermit3.TakerPermit[] memory permits) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](permits.length);
        for (uint256 i; i < permits.length; i++) {
            hashes[i] = keccak256(
                abi.encode(
                    TAKER_PERMIT_TYPEHASH,
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

    function _batchDigest(IPermit3.PermitBatch memory batch, bytes32 domainSeparator)
        internal
        pure
        returns (bytes32)
    {
        bytes32 hashStruct = keccak256(
            abi.encode(PERMIT_BATCH_TYPEHASH, _hashTokens(batch.tokens), _hashTakers(batch.takers), batch.deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, hashStruct));
    }

    function _batchDigestWithWitness(
        IPermit3.PermitBatch memory batch,
        bytes32 witness,
        string memory witnessTypeString,
        bytes32 domainSeparator
    ) internal pure returns (bytes32) {
        bytes32 typeHash = keccak256(abi.encodePacked(WITNESS_STUB, witnessTypeString));
        bytes32 hashStruct = keccak256(
            abi.encode(
                typeHash, _hashTokens(batch.tokens), _hashTakers(batch.takers), batch.deadline, witness
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, hashStruct));
    }

    // ──────────────────── Signing ────────────────────

    function signBatch(IPermit3.PermitBatch memory batch, uint256 pk, bytes32 domainSeparator)
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _batchDigest(batch, domainSeparator));
        return bytes.concat(r, s, bytes1(v));
    }

    function signBatchCompact(IPermit3.PermitBatch memory batch, uint256 pk, bytes32 domainSeparator)
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _batchDigest(batch, domainSeparator));
        bytes32 vs = bytes32((uint256(v) - 27) << 255) | s;
        return bytes.concat(r, vs);
    }

    function signBatchWithWitness(
        IPermit3.PermitBatch memory batch,
        bytes32 witness,
        string memory witnessTypeString,
        uint256 pk,
        bytes32 domainSeparator
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(pk, _batchDigestWithWitness(batch, witness, witnessTypeString, domainSeparator));
        return bytes.concat(r, s, bytes1(v));
    }

    // ──────────────────── Batch builders ────────────────────

    function tokenOnlyBatch(IPermit3.TokenPermit memory p, uint256 deadline)
        internal
        pure
        returns (IPermit3.PermitBatch memory)
    {
        IPermit3.TokenPermit[] memory ts = new IPermit3.TokenPermit[](1);
        ts[0] = p;
        IPermit3.TakerPermit[] memory rs = new IPermit3.TakerPermit[](0);
        return IPermit3.PermitBatch({tokens: ts, takers: rs, deadline: deadline});
    }

    function takerOnlyBatch(IPermit3.TakerPermit memory p, uint256 deadline)
        internal
        pure
        returns (IPermit3.PermitBatch memory)
    {
        IPermit3.TokenPermit[] memory ts = new IPermit3.TokenPermit[](0);
        IPermit3.TakerPermit[] memory rs = new IPermit3.TakerPermit[](1);
        rs[0] = p;
        return IPermit3.PermitBatch({tokens: ts, takers: rs, deadline: deadline});
    }
}
