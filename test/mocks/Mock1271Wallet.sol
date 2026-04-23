// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal EIP-1271 smart-account wallet that delegates signature
///         validation to a fixed EOA signer via ecrecover.
contract Mock1271Wallet {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant INVALID = 0xffffffff;

    address public immutable signer;

    constructor(address _signer) {
        signer = _signer;
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        if (sig.length != 65) return INVALID;
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        address recovered = ecrecover(hash, v, r, s);
        if (recovered != address(0) && recovered == signer) return MAGIC;
        return INVALID;
    }
}
