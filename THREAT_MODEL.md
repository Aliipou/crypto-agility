# crypto-agility — threat model (honest)

A provider-abstraction + negotiation layer. It makes algorithms swappable and refuses
downgrades; it is **not** a complete cryptographic system.

## Provides

- Real Ed25519 sign/verify and X25519 agreement via the vetted `cryptography` library.
- Algorithm selection by id (swap = config change).
- Hybrid signatures that require BOTH halves (fail closed; no silent classical-only).
- Negotiation that refuses to go below a strength floor (anti-downgrade).
- **Authenticated negotiation against an active MITM.** `negotiate_authenticated`
  verifies a peer's Ed25519 signature over a canonical, injective (sorted +
  length-prefixed, domain-separated) encoding of `(peer_offered, nonce)` *before*
  selection. An attacker who rewrites the offered set on the wire cannot forge the
  signature over the rewritten set, so downgrade-by-rewrite fails closed. A nonce binds
  the offer to one exchange; an optional `seen_nonces` set rejects replays.
- Adversarial tests: downgrade-strip, no-mutual, unknown/forged alg-id, hybrid
  both-halves-required, active-MITM offer-rewrite, signature tamper, nonce-mismatch, replay.

## Does NOT provide (out of scope / honest limits)

- **No post-quantum implementation.** ML-DSA / ML-KEM are interface slots that raise
  until a vetted backend (liboqs) is wired in. This package does not give you PQC.
- **Trusts the `cryptography` library** for the classical primitives; their correctness
  and constant-time behavior are out of our hands.
- **Not a TLS / transport stack.** `negotiate_authenticated` authenticates the
  *algorithm-selection step* against an active MITM (the offered set is signed and the
  signature is checked before selecting). It is **still not a full handshake**: it does
  not negotiate or protect application data, and its guarantee is only as strong as the
  binding of `peer_pubkey` to the peer's real identity — establishing that trust (PKI /
  key pinning / a certificate chain) is **out of scope** here. The plain `negotiate`
  remains unauthenticated and is safe only inside an already-authenticated channel.
- **The X25519-KEM is NOT authenticated by this layer.** `negotiate_authenticated`
  binds the *algorithm choice*, not the KEM ciphertext or the resulting shared secret.
  An unauthenticated X25519 exchange is still MITM-able on its own; it is only safe when
  run inside an authenticated channel (e.g. a real TLS handshake). We add no transport
  authentication for the key exchange itself.
- **Owns no long-term secrets.** No key storage, rotation, escrow, HSM, or PKI. Keys
  here are ephemeral. Long-term key lifecycle belongs in a KMS, not here.
- **Side channels / timing / fault attacks** — out of scope.

## Honest status

Real, working classical agility + hybrid/negotiation *structure*, with PQC as an
explicit, unfaked slot. It is the seam through which a system migrates algorithms — not
a drop-in post-quantum security solution.
