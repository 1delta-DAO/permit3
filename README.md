# Permit3

Unified allowance hub for ERC20 transfers **and** protocol position-pulling
operations (borrow, withdraw, unstake, claim, vault redemption, …). Extends
the [Permit2](https://github.com/Uniswap/permit2) model with a second
allowance book for ops that don't fit the ERC20 `transferFrom` shape.

## Two allowance books

```
                     ┌──────────────────────────┐
                     │         Permit3          │
                     │                          │
       approveToken  │  tokenAllowance          │
       transferFrom  │    (user, spender, tok)  │
    ────────────────▶│                          │
                     │  takerAllowance          │
       approveTaker  │    (user, module, ref)   │
           take      │                          │
    ────────────────▶│  take(...) ──────┐       │
                     └──────────────────┼───────┘
                                        │
                                        │  1. ref = keccak256(data)
                                        │  2. _spend allowance on ref
                                        │  3. takeOnBehalf(...)
                                        ▼
                     ┌──────────────────────────┐
                     │     ITakerModule(A)      │   e.g. AaveV3BorrowModule
                     │                          │
                     │   takeOnBehalf(...)      │   calls protocol
                     └──────────────────────────┘
```

- **Token book** — keyed `(user, spender, token)`. Permit2-equivalent.
  A spender calls `permit3.transferFrom(user, to, token, amount)`; Permit3
  decrements the spender's allowance and invokes the token's ERC20
  `transferFrom`.

- **Taker book** — keyed `(user, module, bytes32 ref)` where
  `ref = keccak256(data)`. Any caller invokes
  `permit3.take(module, user, amount, receiver, data)`; Permit3
  decrements the allowance on that ref and calls
  `module.takeOnBehalf(user, amount, receiver, data)`. The module
  performs the protocol-native call (borrow, withdraw, unstake, …).

Permit3 never speaks to a lending/staking protocol directly. All
protocol-specific plumbing lives in single-op modules (`ITakerModule`
for pulls, `IMakerModule` for pushes).

## Why

Systems that pull value from a user's position — borrow-on-behalf,
withdraw-on-behalf, unstake, claim — usually authorise each op via a
signed order plus an admin-controlled module whitelist. That conflates
two different trust decisions:

1. **Which protocols am I willing to interact with?** — user-scoped.
2. **How much am I willing to let this module pull from me right now?** —
   per-order, amount-gated.

Permit3 makes (2) explicit and protocol-agnostic. Users approve Permit3
once per token (or per `(module, position)`), and tune amount caps per
order thereafter — the same ergonomic as Permit2, extended to
debt/withdrawal/unstake. The caller of `take` / `transferFrom` is
unprivileged: the allowance is the only authorisation.

## Repo layout

```
src/
├── permit3/
│   └── Permit3.sol            Allowance hub — token + taker books, take() dispatch
└── interfaces/
    ├── IPermit3.sol           External surface of Permit3
    ├── ITakerModule.sol       Single-method adapter for pull-value ops
    └── IMakerModule.sol       Single-method adapter for push-value ops

script/
└── Deploy.s.sol               Permit3 deployment script
```

See [`src/permit3/README.md`](src/permit3/README.md) for the full design
doc (allowance semantics, `data` layout conventions, security properties,
per-protocol module cheat sheet).

## Usage

### User (one-time per module/protocol)

1. Protocol-native delegation so the module can act on-chain:
   ```solidity
   aaveVariableDebtToken.approveDelegation(borrowModule, type(uint256).max);
   comet.allow(withdrawModule, true);
   morpho.setAuthorization(borrowModule, true);
   ```

2. Permit3 token approval for any ERC20 the module may need to pull:
   ```solidity
   token.approve(permit3, type(uint256).max);
   permit3.approveToken(module, token, cap, expiration);
   ```

### User (per-order, amount-gated)

```solidity
bytes32 ref = keccak256(data);     // same bytes the caller will pass to `take`
permit3.approveTaker(borrowModule, ref, 1_000e6, uint48(block.timestamp + 1 hours));
```

### Caller (per fill)

```solidity
permit3.take(borrowModule, user, 1_000e6, receiver, data);
// internally:
//   ref = keccak256(data)
//   _spend(takerAllowance[user][borrowModule][ref], 1_000e6)
//   borrowModule.takeOnBehalf(user, 1_000e6, receiver, data)
```

Inside `takeOnBehalf`, the module is free to call
`permit3.transferFrom(user, ..., token, amount)` to pull ERC20s for the
op (fees, collateral legs, etc.) — the token book gates those pulls
independently.

## Allowance semantics

| Field                   | Meaning                                                |
|-------------------------|--------------------------------------------------------|
| `amount == uint160.max` | Infinite — not decremented on spend.                   |
| `expiration == 0`       | No expiration.                                         |
| `expiration > 0`        | Allowance expires at `block.timestamp > expiration`.   |

Revocation:
- `revokeToken(spender, token)` — zero a token allowance.
- `revokeTaker(module, ref)` — zero a taker allowance.
- `lockdown(spender)` — event-only signal; off-chain infra sweeps
  indexed pairs via `revokeToken` / `revokeTaker`.

## Signed permits (EIP-712)

`permitBatch(owner, batch, sig)` applies a batch of `TokenPermit[]` and
`TakerPermit[]` in a single call from an owner signature.
`permitBatchWithWitness(...)` additionally binds the signature to an
arbitrary witness (e.g. an order hash) — useful when integrating with
intent/settlement systems that want to commit to Permit3 approvals and
the order payload atomically.

## Security properties

- **Consume-then-call invariant is enforced by Permit3**, not by the
  module. A buggy module cannot bypass the allowance gate.
- **`take()` is `nonReentrant`** — a module cannot re-enter Permit3 to
  inflate its own allowance window mid-op.
- **`ref = keccak256(data)` with no module-side canonicalisation.** The
  bytes a user authorises are the same bytes the module decodes — a
  module can't lie about which position the approval was for.
- **Modules MUST enforce `msg.sender == permit3` in `takeOnBehalf`.**
  Without this check, a direct `takeOnBehalf` call bypasses the
  taker-allowance gate entirely.

### Caveats to surface in UX

- **Infinite taker allowance on a compromised module is worse than
  infinite token approval.** Token compromise drains balances; taker
  compromise can incur max-LTV debt and route proceeds elsewhere.
- **Boolean-only protocols** (Comet `allow`, Morpho `setAuthorization`)
  have no amount cap at the protocol layer — Permit3 is the *only*
  amount gate for those. Module correctness is load-bearing.
- **Two-layer revocation.** To fully lock out a compromised module, a
  user must revoke at Permit3 *and* revoke the protocol-native
  delegation.

## Build & test

```bash
forge build
forge test -vvv
```

## Status

Implemented:
- Token book (`approveToken` / `transferFrom` / `revokeToken`).
- Taker book (`approveTaker` / `take` / `revokeTaker`).
- `take()` dispatch with `nonReentrant`, `ref = keccak256(data)`, and
  amount spend.
- `uint160.max` infinite semantics; `expiration == 0` sentinel.
- `ITakerModule` / `IMakerModule` single-method adapter interfaces.
- EIP-712 `permitBatch` / `permitBatchWithWitness`.

Not yet implemented (contributions welcome):
- Reference taker/maker modules for Aave v3, Comet, Morpho Blue,
  Compound v2, Lido.
- `revokeAll(module)` helper that also calls the module's per-protocol
  revoke path.
- Foundry invariant suite asserting `data` round-trips cleanly through
  each module.

## License

MIT.
