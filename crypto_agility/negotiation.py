"""Algorithm negotiation with an anti-downgrade floor — refuse, never degrade.

``negotiate`` picks the strongest mutual algorithm above a floor, but it trusts
its inputs: an active MITM who rewrites BOTH offered sets can move the whole
negotiation below the floor without either party noticing. ``negotiate_authenticated``
closes that gap by binding the peer's offered set to an Ed25519 signature over a
canonical, injective encoding of ``(offered, nonce)``; the offer is verified
*before* selection and any rewrite invalidates the signature (fail closed).
"""

from __future__ import annotations

from enum import IntEnum

from .classical import Ed25519SignatureProvider
from .errors import NegotiationError, VerificationError


class AlgorithmStrength(IntEnum):
    CLASSICAL = 1      # Ed25519, X25519 — quantum-vulnerable
    HYBRID = 2         # classical + PQC
    POST_QUANTUM = 3   # pure PQC


_STRENGTH = {
    "Ed25519": AlgorithmStrength.CLASSICAL,
    "X25519": AlgorithmStrength.CLASSICAL,
    "ML-DSA-65": AlgorithmStrength.POST_QUANTUM,
    "ML-KEM-768": AlgorithmStrength.POST_QUANTUM,
    "Ed25519+ML-DSA-65": AlgorithmStrength.HYBRID,
    "X25519+ML-KEM-768": AlgorithmStrength.HYBRID,
}


def strength(alg_id: str) -> AlgorithmStrength:
    try:
        return _STRENGTH[alg_id]
    except KeyError as e:
        raise NegotiationError(f"unknown algorithm strength: {alg_id!r}") from e


def negotiate(local_offered, peer_offered, floor: AlgorithmStrength = AlgorithmStrength.CLASSICAL) -> str:
    """Pick the strongest mutually-supported algorithm; refuse if it is below ``floor``.

    This is the explicit anti-downgrade control: an attacker who strips the strong
    algorithm from the offered set causes a refusal (NegotiationError), never a
    silent fallback below the floor.
    """
    peer = set(peer_offered)
    mutual = [a for a in local_offered if a in peer]
    if not mutual:
        raise NegotiationError("no mutually-supported algorithm")
    best = max(mutual, key=strength)
    if strength(best) < floor:
        raise NegotiationError(
            f"best mutual algorithm {best!r} ({strength(best).name}) is below floor "
            f"{AlgorithmStrength(floor).name} — refusing to downgrade"
        )
    return best


# --- Authenticated negotiation: bind the offered set to a signature -----------

_OFFER_DOMAIN = b"crypto-agility/negotiate-offer/v1"


def _u32(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFF:
        raise NegotiationError(f"length out of range for canonical encoding: {n}")
    return n.to_bytes(4, "big")


def canonical_offer(offered, nonce: bytes) -> bytes:
    """Canonical, injective encoding of an offered set + nonce, for signing.

    The signature must bind *exactly* what was offered, so the encoding has to be
    unambiguous: two different ``(offered, nonce)`` inputs can never collide onto
    the same bytes (injective). We achieve that by

    * sorting + de-duplicating the alg-ids (order/duplication carry no meaning, so
      both sides derive the same canonical set regardless of wire order), and
    * length-prefixing every field (a domain tag, the nonce, the count, then each
      UTF-8 alg-id) with a fixed-width 32-bit big-endian length.

    Length-prefixing makes the concatenation unambiguous: no field's bytes can be
    re-parsed as a different field boundary, so ``["A", "BC"]`` and ``["AB", "C"]``
    encode differently. Sorting is what lets a verifier reconstruct the exact bytes
    the signer signed without trusting wire order.
    """
    if not isinstance(nonce, (bytes, bytearray)):
        raise NegotiationError("nonce must be bytes")
    algs = sorted(set(offered))
    parts = [_u32(len(_OFFER_DOMAIN)), _OFFER_DOMAIN,
             _u32(len(nonce)), bytes(nonce),
             _u32(len(algs))]
    for alg in algs:
        enc = alg.encode("utf-8")
        parts.append(_u32(len(enc)))
        parts.append(enc)
    return b"".join(parts)


def sign_offer(offered, nonce: bytes, private_key: bytes,
               signer: Ed25519SignatureProvider | None = None) -> bytes:
    """Produce an Ed25519 signature over the canonical encoding of ``(offered, nonce)``.

    The returned signature is what a peer publishes alongside its offered set so a
    remote party can authenticate it. Uses the existing classical Ed25519 provider.
    """
    signer = signer or Ed25519SignatureProvider()
    return signer.sign(private_key, canonical_offer(offered, nonce))


def negotiate_authenticated(local_offered, peer_offered, peer_offered_sig: bytes,
                            peer_pubkey: bytes, *,
                            floor: AlgorithmStrength = AlgorithmStrength.CLASSICAL,
                            nonce: bytes,
                            seen_nonces=None,
                            verifier: Ed25519SignatureProvider | None = None) -> str:
    """Negotiate against an *authenticated* peer offer — defeats downgrade-by-rewrite.

    Plain :func:`negotiate` trusts both offered sets, so an active MITM who rewrites
    BOTH sides moves the whole negotiation below the floor undetected. Here the peer
    signs (Ed25519) a canonical encoding of ``(peer_offered, nonce)``. We verify that
    signature **before** selecting; an attacker who rewrites ``peer_offered`` cannot
    produce a matching signature over the rewritten set, so the verify fails and we
    refuse (fail closed) rather than downgrade.

    ``nonce`` binds the offer to this exchange; pass a mutable ``seen_nonces`` set to
    get replay protection — a nonce already seen is rejected as stale. This still does
    NOT authenticate the X25519-KEM or replace a TLS handshake; it authenticates the
    *algorithm negotiation* only, and only as strong as the binding of ``peer_pubkey``
    to the peer's identity (out of scope here — no PKI).
    """
    verifier = verifier or Ed25519SignatureProvider()
    transcript = canonical_offer(peer_offered, nonce)
    if not verifier.verify(peer_pubkey, transcript, peer_offered_sig):
        raise VerificationError(
            "peer offered-set signature did not verify — refusing to negotiate "
            "(possible active MITM rewrite of the offered set)"
        )
    if seen_nonces is not None:
        if nonce in seen_nonces:
            raise NegotiationError("stale nonce — replayed authenticated offer rejected")
        seen_nonces.add(nonce)
    return negotiate(local_offered, peer_offered, floor)
