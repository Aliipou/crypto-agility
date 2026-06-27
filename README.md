# crypto-agility

A cryptographic-agility provider: **algorithms are data, not code.** A system selects
signature / KEM algorithms by string `alg_id` through a registry, so swapping an
algorithm — including migrating to post-quantum — is a configuration change, not a
rewrite. This is the agility the rest of the ecosystem needs so that authority never
rests on a single, breakable algorithm.

## What is real here (honest)

- **Real classical crypto** via the vetted `cryptography` library: **Ed25519**
  signatures and **X25519** key agreement (wrapped as a KEM). These are
  quantum-vulnerable — they are what you migrate *from*.
- **PQC slots are real interfaces, not faked implementations.** `ML-DSA-65` (FIPS 204)
  and `ML-KEM-768` (FIPS 203) are selectable algorithm-ids, but this package does
  **not** implement the primitives — every call fails closed with a message pointing
  at a vetted backend (liboqs / python-oqs). Rolling your own PQC is dangerous; we
  don't.
- **Hybrid fails closed.** A hybrid signature (classical + PQC) requires **both**
  halves to verify and never silently degrades to classical-only. With the real PQC
  slot you cannot even produce a hybrid keypair — by design.
- **Anti-downgrade negotiation.** `negotiate(local, peer, floor)` picks the strongest
  mutually-supported algorithm and **refuses** to go below `floor`. Stripping the
  strong algorithm causes a refusal, not a downgrade.
- **Authenticated negotiation (anti-rewrite).** `negotiate(...)` trusts its inputs, so
  an *active* MITM who rewrites BOTH offered sets can move the whole negotiation below
  the floor undetected. `negotiate_authenticated(...)` closes that: the peer signs
  (Ed25519) a canonical, length-prefixed encoding of its `(offered, nonce)`, and the
  signature is **verified before selection**. Rewriting the offered set invalidates the
  signature, so downgrade-by-rewrite fails closed. An optional `seen_nonces` set gives
  replay protection. This authenticates the *algorithm negotiation* only — see below.

## Scope (deliberately narrow)

Provider abstraction + negotiation only. **Not** a KMS, key store, PKI, or TLS stack.
It owns no long-term secrets (only ephemeral keys in tests/usage). See `THREAT_MODEL.md`.

## Use

```python
from crypto_agility import default_registry, negotiate, AlgorithmStrength

reg = default_registry()
ed = reg.signature("Ed25519")
kp = ed.generate_keypair()
sig = ed.sign(kp.private_key, b"msg")
assert ed.verify(kp.public_key, b"msg", sig)

negotiate(["Ed25519+ML-DSA-65", "Ed25519"], ["Ed25519+ML-DSA-65"],
          floor=AlgorithmStrength.HYBRID)   # -> "Ed25519+ML-DSA-65"
```

```python
from crypto_agility import negotiate_authenticated, sign_offer, AlgorithmStrength

# Peer signs exactly what it offers, bound to a per-exchange nonce.
offered, nonce = ["Ed25519+ML-DSA-65", "Ed25519"], b"exchange-nonce-0001"
sig = sign_offer(offered, nonce, peer_kp.private_key)

# Verifier checks the signature BEFORE selecting; a rewritten offer fails closed.
negotiate_authenticated(["Ed25519+ML-DSA-65", "Ed25519"], offered, sig,
                        peer_kp.public_key,
                        floor=AlgorithmStrength.HYBRID, nonce=nonce)  # -> "Ed25519+ML-DSA-65"
```

```bash
python -m unittest discover -s tests -t .
```
