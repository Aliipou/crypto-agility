"""Versioned provider interfaces. Algorithms are data (an ``alg_id`` string)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

PROVIDER_API_VERSION = "1.0"


@dataclass(frozen=True)
class SignatureKeyPair:
    alg_id: str
    public_key: bytes
    private_key: bytes  # ephemeral; this package owns no long-term secrets


@dataclass(frozen=True)
class KemKeyPair:
    alg_id: str
    public_key: bytes
    private_key: bytes


@dataclass(frozen=True)
class Encapsulation:
    alg_id: str
    ciphertext: bytes      # for X25519-KEM: the ephemeral public key
    shared_secret: bytes


@runtime_checkable
class SignatureProvider(Protocol):
    alg_id: str

    def generate_keypair(self) -> SignatureKeyPair: ...
    def sign(self, private_key: bytes, message: bytes) -> bytes: ...
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


@runtime_checkable
class KemProvider(Protocol):
    alg_id: str

    def generate_keypair(self) -> KemKeyPair: ...
    def encapsulate(self, public_key: bytes) -> Encapsulation: ...
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes: ...
