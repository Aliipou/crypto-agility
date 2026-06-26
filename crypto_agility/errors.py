"""Exception hierarchy for crypto_agility.

All errors derive from :class:`CryptoAgilityError` so callers can catch the
whole family with one ``except``. Each subclass marks a distinct *fail-closed*
condition — the library prefers raising over returning a degraded result.
"""

from __future__ import annotations


class CryptoAgilityError(Exception):
    """Base class for every error raised by this package."""


class UnknownAlgorithmError(CryptoAgilityError):
    """An algorithm-id was requested that is not present in the registry.

    Raised on lookup of an unregistered / forged / typo'd ``alg_id``.
    Selecting an unknown algorithm must never silently succeed.
    """


class NotImplementedAlgorithmError(CryptoAgilityError, NotImplementedError):
    """A registered algorithm exists as an interface slot but has no backend.

    Used by the PQC adapters (ML-DSA-65, ML-KEM-768): the slot is real and
    selectable, but the underlying primitive is not implemented in this
    package. The message points at a real library (liboqs / python-oqs).

    It also subclasses the builtin :class:`NotImplementedError` so existing
    ``except NotImplementedError`` handlers keep working.
    """


class NegotiationError(CryptoAgilityError):
    """Algorithm negotiation could not produce an acceptable result.

    Raised when there is no mutually-supported algorithm, or the best
    mutually-supported algorithm sits below the required ``floor``. This is
    the explicit anti-downgrade signal: refuse rather than degrade.
    """


class VerificationError(CryptoAgilityError):
    """A signature failed to verify.

    Raised (instead of returning ``False``) by paths that must fail closed,
    e.g. a hybrid verify where one half does not verify.
    """
