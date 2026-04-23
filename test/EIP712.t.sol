// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Permit3} from "../src/permit3/Permit3.sol";

/// @notice Port of `permit2/test/EIP712.t.sol` — domain-separator
///         construction and chain-fork behavior.
contract EIP712Test is Test {
    Permit3 internal permit3;

    function setUp() public {
        permit3 = new Permit3();
    }

    function testDomainSeparator() public view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Permit3"),
                keccak256("1"),
                block.chainid,
                address(permit3)
            )
        );
        assertEq(permit3.DOMAIN_SEPARATOR(), expected);
    }

    /// @dev Domain separator is stored as immutable — after a chain fork its
    ///      chainId field no longer matches the active chain, by design
    ///      (Permit2 has the same property on its bare EIP712 contract;
    ///      only AllowanceTransfer adds a fork-aware rebuild).
    function testDomainSeparatorImmutableAfterFork() public {
        bytes32 before = permit3.DOMAIN_SEPARATOR();
        vm.chainId(block.chainid + 1);
        assertEq(permit3.DOMAIN_SEPARATOR(), before);
    }
}
