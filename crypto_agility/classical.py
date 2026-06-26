"""Real classical adapters via the vetted ``cryptography`` library.

Ed25519 signatures and X25519 key agreement (wrapped as a KEM). These are
*quantum-vulnerable* (Shor breaks the discrete log) — they exist so the agility
layer has real, working algorithms to swap *from*, toward PQC.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .interfaces import Encapsulation, KemKeyPair, SignatureKeyPair

_RAW = serialization.Encoding.Raw


def _priv_bytes(k) -> bytes:
    return k.private_bytes(_RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _pub_bytes(k) -> bytes:
    return k.public_bytes(_RAW, serialization.PublicFormat.Raw)


def _hkdf(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"crypto-agility/X25519-KEM").derive(shared)


class Ed25519SignatureProvider:
    alg_id = "Ed25519"

    def generate_keypair(self) -> SignatureKeyPair:
        sk = Ed25519PrivateKey.generate()
        return SignatureKeyPair(self.alg_id, _pub_bytes(sk.public_key()), _priv_bytes(sk))

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(private_key).sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except InvalidSignature:
            return False


class X25519KemProvider:
    """X25519 ECDH wrapped as a KEM: encapsulate makes an ephemeral key, derives a
    shared secret via HKDF; the 'ciphertext' is the ephemeral public key."""

    alg_id = "X25519"

    def generate_keypair(self) -> KemKeyPair:
        sk = X25519PrivateKey.generate()
        return KemKeyPair(self.alg_id, _pub_bytes(sk.public_key()), _priv_bytes(sk))

    def encapsulate(self, public_key: bytes) -> Encapsulation:
        eph = X25519PrivateKey.generate()
        shared = eph.exchange(X25519PublicKey.from_public_bytes(public_key))
        return Encapsulation(self.alg_id, _pub_bytes(eph.public_key()), _hkdf(shared))

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        sk = X25519PrivateKey.from_private_bytes(private_key)
        shared = sk.exchange(X25519PublicKey.from_public_bytes(ciphertext))
        return _hkdf(shared)
