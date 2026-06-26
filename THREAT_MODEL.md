# crypto-agility — threat model (honest)

A provider-abstraction + negotiation layer. It makes algorithms swappable and refuses
downgrades; it is **not** a complete cryptographic system.

## Provides

- Real Ed25519 sign/verify and X25519 agreement via the vetted `cryptography` library.
- Algorithm selection by id (swap = config change).
- Hybrid signatures that require BOTH halves (fail closed; no silent classical-only).
- Negotiation that refuses to go below a strength floor (anti-downgrade).
- Adversarial tests: downgrade-strip, no-mutual, unknown/forged alg-id, hybrid both-halves-required.

## Does NOT provide (out of scope / honest limits)

- **No post-quantum implementation.** ML-DSA / ML-KEM are interface slots that raise
  until a vetted backend (liboqs) is wired in. This package does not give you PQC.
- **Trusts the `cryptography` library** for the classical primitives; their correctness
  and constant-time behavior are out of our hands.
- **Not a TLS / transport stack.** Negotiation here is an algorithm-selection helper,
  not a full handshake; it does not authenticate the peer or protect the negotiation
  channel itself (a real handshake must sign/MAC the transcript).
- **Owns no long-term secrets.** No key storage, rotation, escrow, HSM, or PKI. Keys
  here are ephemeral. Long-term key lifecycle belongs in a KMS, not here.
- **Side channels / timing / fault attacks** — out of scope.

## Honest status

Real, working classical agility + hybrid/negotiation *structure*, with PQC as an
explicit, unfaked slot. It is the seam through which a system migrates algorithms — not
a drop-in post-quantum security solution.
