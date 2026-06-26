"""Hybrid signatures — classical + PQC, fail-closed.

A hybrid signature requires BOTH halves to verify. It never silently degrades to
classical-only: if the PQC backend is unavailable, signing/keygen raises (the PQC
slot's NotImplementedAlgorithmError propagates). A break in either single algorithm
alone is therefore survivable.
"""

from __future__ import annotations

import struct

from .interfaces import SignatureKeyPair


def _pack(*parts: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(p)) + p for p in parts)


def _unpack(blob: bytes, n: int) -> list[bytes]:
    out, off = [], 0
    for _ in range(n):
        (length,) = struct.unpack(">I", blob[off:off + 4])
        off += 4
        out.append(blob[off:off + length])
        off += length
    return out


class HybridSignatureProvider:
    def __init__(self, classical_provider, pqc_provider) -> None:
        self.classical = classical_provider
        self.pqc = pqc_provider
        self.alg_id = f"{classical_provider.alg_id}+{pqc_provider.alg_id}"

    def generate_keypair(self) -> SignatureKeyPair:
        c = self.classical.generate_keypair()
        p = self.pqc.generate_keypair()  # raises if PQC is an unimplemented slot (fail closed)
        return SignatureKeyPair(self.alg_id, _pack(c.public_key, p.public_key),
                                _pack(c.private_key, p.private_key))

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        c_priv, p_priv = _unpack(private_key, 2)
        return _pack(self.classical.sign(c_priv, message), self.pqc.sign(p_priv, message))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        c_pub, p_pub = _unpack(public_key, 2)
        c_sig, p_sig = _unpack(signature, 2)
        # BOTH must verify. AND, not OR — a single valid half is not enough.
        return bool(self.classical.verify(c_pub, message, c_sig)
                    and self.pqc.verify(p_pub, message, p_sig))
