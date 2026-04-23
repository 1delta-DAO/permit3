// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Permit3Test} from "./base/Permit3Test.sol";
import {IPermit3} from "../src/interfaces/IPermit3.sol";
import {Mock1271Wallet} from "./mocks/Mock1271Wallet.sol";
import {MockTakerModule} from "./mocks/MockTakerModule.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// @notice EIP-712 signed-permit flows: happy-path batches (token / taker /
///         combined), per-entry nonce advancement, deadline, replay, witness,
///         EIP-1271 smart-wallet signatures, malleability, and EIP-2098
///         compact signatures. Ports the relevant cases from
///         `permit2/test/AllowanceTransferTest.t.sol` and
///         `permit2/test/CompactSignature.t.sol`.
contract PermitsTest is Permit3Test {
    event TokenApproval(
        address indexed user, address indexed spender, address indexed token, uint160 amount, uint48 expiration
    );
    event TakerApproval(
        address indexed user, address indexed module, bytes32 indexed ref, uint160 amount, uint48 expiration
    );

    address internal constant SPENDER = address(0xB0BB);

    function setUp() public {
        _baseSetup();
    }

    // ──────────────────── Happy-path batches ────────────────────

    function testPermitBatchTokenOnly() public {
        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit({
                spender: SPENDER,
                token: address(token0),
                amount: DEFAULT_AMOUNT,
                expiration: defaultExpiration,
                nonce: 0
            }),
            defaultDeadline
        );
        bytes memory sig = signBatch(batch, alicePk, DOMAIN_SEPARATOR);

        vm.expectEmit(true, true, true, true);
        emit TokenApproval(alice, SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration);
        permit3.permitBatch(alice, batch, sig);

        (uint160 amount, uint48 expiration, uint48 nonce) = permit3.tokenAllowance(alice, SPENDER, address(token0));
        assertEq(amount, DEFAULT_AMOUNT);
        assertEq(expiration, defaultExpiration);
        assertEq(nonce, 1, "nonce advances by 1");
    }

    function testPermitBatchTakerOnly() public {
        MockERC20 borrowToken = new MockERC20();
        MockTakerModule mod = new MockTakerModule(address(permit3), address(borrowToken));

        bytes32 ref = keccak256(hex"aa");
        IPermit3.PermitBatch memory batch = takerOnlyBatch(
            IPermit3.TakerPermit({
                module: address(mod),
                ref: ref,
                amount: DEFAULT_AMOUNT,
                expiration: defaultExpiration,
                nonce: 0
            }),
            defaultDeadline
        );
        bytes memory sig = signBatch(batch, alicePk, DOMAIN_SEPARATOR);

        vm.expectEmit(true, true, true, true);
        emit TakerApproval(alice, address(mod), ref, DEFAULT_AMOUNT, defaultExpiration);
        permit3.permitBatch(alice, batch, sig);

        (uint160 amount,, uint48 nonce) = permit3.takerAllowance(alice, address(mod), ref);
        assertEq(amount, DEFAULT_AMOUNT);
        assertEq(nonce, 1);
    }

    function testPermitBatchCombined() public {
        MockERC20 borrowToken = new MockERC20();
        MockTakerModule mod = new MockTakerModule(address(permit3), address(borrowToken));

        IPermit3.TokenPermit[] memory ts = new IPermit3.TokenPermit[](2);
        ts[0] = IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0);
        ts[1] = IPermit3.TokenPermit(SPENDER, address(token1), 2e18, defaultExpiration, 0);
        IPermit3.TakerPermit[] memory rs = new IPermit3.TakerPermit[](1);
        rs[0] = IPermit3.TakerPermit(address(mod), keccak256(hex"01"), 3e18, defaultExpiration, 0);

        IPermit3.PermitBatch memory batch = IPermit3.PermitBatch(ts, rs, defaultDeadline);
        bytes memory sig = signBatch(batch, alicePk, DOMAIN_SEPARATOR);
        permit3.permitBatch(alice, batch, sig);

        (uint160 a0,, uint48 n0) = permit3.tokenAllowance(alice, SPENDER, address(token0));
        (uint160 a1,, uint48 n1) = permit3.tokenAllowance(alice, SPENDER, address(token1));
        (uint160 a2,, uint48 n2) = permit3.takerAllowance(alice, address(mod), keccak256(hex"01"));
        assertEq(a0, DEFAULT_AMOUNT);
        assertEq(a1, 2e18);
        assertEq(a2, 3e18);
        assertEq(n0, 1);
        assertEq(n1, 1);
        assertEq(n2, 1);
    }

    // ──────────────────── Nonce mechanics ────────────────────

    function testPermitBatchReplayFails() public {
        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatch(batch, alicePk, DOMAIN_SEPARATOR);

        permit3.permitBatch(alice, batch, sig);
        vm.expectRevert(IPermit3.InvalidPermitNonce.selector);
        permit3.permitBatch(alice, batch, sig);
    }

    function testPermitBatchWrongNonceFails() public {
        // Alice's token0/SPENDER nonce starts at 0; signed permit claims 1.
        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 1), defaultDeadline
        );
        bytes memory sig = signBatch(batch, alicePk, DOMAIN_SEPARATOR);

        vm.expectRevert(IPermit3.InvalidPermitNonce.selector);
        permit3.permitBatch(alice, batch, sig);
    }

    function testInvalidateVoidsOutstandingSignedPermit() public {
        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatch(batch, alicePk, DOMAIN_SEPARATOR);

        vm.prank(alice);
        permit3.invalidateTokenNonces(SPENDER, address(token0), 1);

        vm.expectRevert(IPermit3.InvalidPermitNonce.selector);
        permit3.permitBatch(alice, batch, sig);
    }

    // ──────────────────── Deadline / signature-shape failures ────────────────────

    function testPermitBatchDeadlinePassedReverts() public {
        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatch(batch, alicePk, DOMAIN_SEPARATOR);

        vm.warp(defaultDeadline + 1);
        vm.expectRevert(IPermit3.PermitExpired.selector);
        permit3.permitBatch(alice, batch, sig);
    }

    function testPermitBatchWrongSignerReverts() public {
        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatch(batch, bobPk, DOMAIN_SEPARATOR);
        vm.expectRevert(IPermit3.InvalidPermitSignature.selector);
        permit3.permitBatch(alice, batch, sig);
    }

    function testPermitBatchBadSigLengthReverts() public {
        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatch(batch, alicePk, DOMAIN_SEPARATOR);
        bytes memory extra = bytes.concat(sig, hex"01");
        assertEq(extra.length, 66);

        vm.expectRevert(IPermit3.InvalidPermitSignature.selector);
        permit3.permitBatch(alice, batch, extra);
    }

    function testPermitBatchHighSReverts() public {
        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatch(batch, alicePk, DOMAIN_SEPARATOR);

        // Flip (r, s, v) to the malleable dual (r, n-s, v^1) — valid as a
        // curve point but rejected by Permit3's low-s guard.
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        bytes32 sFlip = bytes32(SECP256K1_N - uint256(s));
        uint8 vFlip = v == 27 ? 28 : 27;
        bytes memory mal = bytes.concat(r, sFlip, bytes1(vFlip));

        vm.expectRevert(IPermit3.InvalidPermitSignature.selector);
        permit3.permitBatch(alice, batch, mal);
    }

    function testPermitBatchBadVReverts() public {
        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatch(batch, alicePk, DOMAIN_SEPARATOR);
        // Overwrite v with an illegal value (e.g. 26).
        sig[64] = bytes1(uint8(26));
        vm.expectRevert(IPermit3.InvalidPermitSignature.selector);
        permit3.permitBatch(alice, batch, sig);
    }

    // ──────────────────── EIP-2098 compact signatures ────────────────────

    function testPermitBatchCompactSig() public {
        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatchCompact(batch, alicePk, DOMAIN_SEPARATOR);
        assertEq(sig.length, 64);

        permit3.permitBatch(alice, batch, sig);
        (uint160 amount,,) = permit3.tokenAllowance(alice, SPENDER, address(token0));
        assertEq(amount, DEFAULT_AMOUNT);
    }

    // ──────────────────── EIP-1271 smart-wallet signatures ────────────────────

    function testPermitBatchEIP1271Accepts() public {
        Mock1271Wallet wallet = new Mock1271Wallet(alice);

        // Wallet needs ERC20 balance/approval to act as owner.
        token0.mint(address(wallet), 1e18);
        vm.prank(address(wallet));
        token0.approve(address(permit3), type(uint256).max);

        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        // Sign with alice's EOA key — the wallet delegates to that signer.
        bytes memory sig = signBatch(batch, alicePk, DOMAIN_SEPARATOR);
        permit3.permitBatch(address(wallet), batch, sig);

        (uint160 amount,, uint48 nonce) = permit3.tokenAllowance(address(wallet), SPENDER, address(token0));
        assertEq(amount, DEFAULT_AMOUNT);
        assertEq(nonce, 1);
    }

    function testPermitBatchEIP1271RejectsWrongSigner() public {
        Mock1271Wallet wallet = new Mock1271Wallet(alice);
        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatch(batch, bobPk, DOMAIN_SEPARATOR);
        vm.expectRevert(IPermit3.InvalidPermitSignature.selector);
        permit3.permitBatch(address(wallet), batch, sig);
    }

    // ──────────────────── Witness-bound ────────────────────

    function testPermitBatchWithWitnessHappyPath() public {
        bytes32 witness = keccak256("ORDER_HASH_V1");
        string memory typeStr = "bytes32 witness)";

        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatchWithWitness(batch, witness, typeStr, alicePk, DOMAIN_SEPARATOR);

        permit3.permitBatchWithWitness(alice, batch, witness, typeStr, sig);
        (uint160 amount,,) = permit3.tokenAllowance(alice, SPENDER, address(token0));
        assertEq(amount, DEFAULT_AMOUNT);
    }

    function testPermitBatchWithWitnessWrongWitnessReverts() public {
        bytes32 witness = keccak256("ORDER_HASH_V1");
        string memory typeStr = "bytes32 witness)";

        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatchWithWitness(batch, witness, typeStr, alicePk, DOMAIN_SEPARATOR);

        vm.expectRevert(IPermit3.InvalidPermitSignature.selector);
        permit3.permitBatchWithWitness(alice, batch, keccak256("DIFFERENT"), typeStr, sig);
    }

    function testPermitBatchWithWitnessWrongTypeStringReverts() public {
        bytes32 witness = keccak256("ORDER_HASH_V1");

        IPermit3.PermitBatch memory batch = tokenOnlyBatch(
            IPermit3.TokenPermit(SPENDER, address(token0), DEFAULT_AMOUNT, defaultExpiration, 0), defaultDeadline
        );
        bytes memory sig = signBatchWithWitness(batch, witness, "bytes32 witness)", alicePk, DOMAIN_SEPARATOR);

        vm.expectRevert(IPermit3.InvalidPermitSignature.selector);
        permit3.permitBatchWithWitness(alice, batch, witness, "bytes32 other)", sig);
    }
}
