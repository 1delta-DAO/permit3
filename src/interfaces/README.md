# Interfaces

Public interfaces for Permit3 and its adapter modules.

## IPermit3.sol

External surface of the Permit3 allowance hub. Two allowance books:

**Token book** — Permit2-equivalent, keyed `(user, spender, token)`.

| Function | Description |
|----------|-------------|
| `approveToken(spender, token, amount, expiration)` | Authorise a spender to pull `token` from the caller up to `amount`. |
| `transferFrom(user, to, token, amount)` | Called by the spender to pull ERC20s. Decrements the allowance. |
| `tokenAllowance(user, spender, token)` | Read `(amount, expiration, nonce)`. |
| `revokeToken(spender, token)` | Zero a token allowance. |

**Taker book** — keyed `(user, module, bytes32 ref)` where `ref = keccak256(data)`.

| Function | Description |
|----------|-------------|
| `approveTaker(module, ref, amount, expiration)` | Authorise a taker module to pull `amount` from the position identified by `ref`. |
| `take(module, user, amount, receiver, data)` | Amount-gated dispatch: Permit3 decrements the user's taker allowance on `keccak256(data)`, then calls `module.takeOnBehalf(user, amount, receiver, data)`. |
| `takerAllowance(user, module, ref)` | Read `(amount, expiration, nonce)`. |
| `revokeTaker(module, ref)` | Zero a taker allowance. |

**Signed permits** (EIP-712):

| Function | Description |
|----------|-------------|
| `permitBatch(owner, batch, sig)` | Apply a batch of `TokenPermit[]` + `TakerPermit[]` from a signature. |
| `permitBatchWithWitness(owner, batch, witness, witnessTypeString, sig)` | Same as `permitBatch` but binds the signature to a caller-defined witness (e.g. an order hash). |
| `lockdown(spender)` | Event-only signal — off-chain infra sweeps specific pairs via `revokeToken` / `revokeTaker`. |

## ITakerModule.sol

Adapter interface implemented by single-operation "pull value from a position" modules (borrow, withdraw, unstake, claim, redeem, …).

```solidity
function takeOnBehalf(address onBehalfOf, uint256 amount, address receiver, bytes calldata data) external;
```

Called only by Permit3 after the allowance gate has been decremented. The module's first statement MUST be `require(msg.sender == permit3)` — without it, the taker-allowance gate can be bypassed. `data` is the exact byte string the user authorised (`ref = keccak256(data)`).

Examples of concrete modules: `AaveV3BorrowModule`, `AaveV3WithdrawModule`, `MorphoBlueBorrowModule`, `CometWithdrawModule`, `LidoUnstakeModule`.

## IMakerModule.sol

Adapter interface implemented by single-operation "push value into a position" modules (deposit, repay, supply, mint).

```solidity
function makeOnBehalf(address onBehalfOf, uint256 amount, bytes calldata data) external;
```

The module pulls the funding token from `onBehalfOf` via `permit3.transferFrom(...)` — the Permit3 token allowance is the only gate, so any caller may invoke `makeOnBehalf`.

Examples: `AaveV3DepositModule`, `AaveV3RepayModule`, `MorphoBlueSupplyModule`, `CometSupplyModule`.
