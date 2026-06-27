"""crypto_agility — a cryptographic-agility provider.

Algorithms are *data, not code*: a system selects signature / KEM
algorithms by string algorithm-id through a registry, so swapping an
algorithm is a configuration change rather than a code change.

Design goals
------------
* Versioned ``SignatureProvider`` and ``KemProvider`` interfaces, each
  tagged with a string ``alg_id``.
* A registry keyed by ``alg_id``; selection is a lookup.
* Real classical adapters via the vetted ``cryptography`` library
  (Ed25519 signatures, X25519 key agreement).
* A PQC adapter *slot* (ML-DSA-65, ML-KEM-768) that is interface-complete
  but raises ``NotImplementedError`` pointing at liboqs — honest, not faked.
* A hybrid signature provider (classical + PQC) that *fails closed*: it
  requires BOTH halves and never silently degrades to classical-only.
* ``negotiate(...)`` that selects the strongest mutually-supported
  algorithm and refuses to go below a ``floor`` (no silent downgrade).

This package is deliberately narrow: it is a provider abstraction plus
negotiation. It is NOT a KMS, a key store, or a PKI, and it owns no
long-term secrets.
"""

from .errors import (
    CryptoAgilityError,
    UnknownAlgorithmError,
    NotImplementedAlgorithmError,
    NegotiationError,
    VerificationError,
)
from .interfaces import (
    SignatureProvider,
    KemProvider,
    SignatureKeyPair,
    KemKeyPair,
    Encapsulation,
    PROVIDER_API_VERSION,
)
from .registry import Registry, default_registry
from .negotiation import (
    negotiate,
    negotiate_authenticated,
    sign_offer,
    canonical_offer,
    AlgorithmStrength,
)
from . import classical
from . import pqc
from . import hybrid

__all__ = [
    "CryptoAgilityError",
    "UnknownAlgorithmError",
    "NotImplementedAlgorithmError",
    "NegotiationError",
    "VerificationError",
    "SignatureProvider",
    "KemProvider",
    "SignatureKeyPair",
    "KemKeyPair",
    "Encapsulation",
    "PROVIDER_API_VERSION",
    "Registry",
    "default_registry",
    "negotiate",
    "negotiate_authenticated",
    "sign_offer",
    "canonical_offer",
    "AlgorithmStrength",
    "classical",
    "pqc",
    "hybrid",
]

__version__ = "0.1.0"
