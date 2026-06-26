"""Algorithm negotiation with an anti-downgrade floor — refuse, never degrade."""

from __future__ import annotations

from enum import IntEnum

from .errors import NegotiationError


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
    except KeyError:
        raise NegotiationError(f"unknown algorithm strength: {alg_id!r}")


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
