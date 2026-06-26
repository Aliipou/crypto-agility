"""Post-quantum adapter SLOTS — real interfaces, not faked implementations.

ML-DSA-65 (FIPS 204) signatures and ML-KEM-768 (FIPS 203) key encapsulation are
selectable algorithm-ids, but this package does NOT implement the primitives.
Rolling your own PQC is dangerous; wire a vetted backend (liboqs / python-oqs)
behind these slots. Until then every operation fails closed.
"""

from __future__ import annotations

from .errors import NotImplementedAlgorithmError
from .interfaces import Encapsulation, KemKeyPair, SignatureKeyPair

_HINT = ("{alg} is a real interface slot but unimplemented here. Install a vetted "
         "PQC backend (liboqs / python-oqs) and wire it behind this provider.")


class MLDSA65SignatureProvider:
    alg_id = "ML-DSA-65"

    def generate_keypair(self) -> SignatureKeyPair:
        raise NotImplementedAlgorithmError(_HINT.format(alg=self.alg_id))

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        raise NotImplementedAlgorithmError(_HINT.format(alg=self.alg_id))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        raise NotImplementedAlgorithmError(_HINT.format(alg=self.alg_id))


class MLKEM768KemProvider:
    alg_id = "ML-KEM-768"

    def generate_keypair(self) -> KemKeyPair:
        raise NotImplementedAlgorithmError(_HINT.format(alg=self.alg_id))

    def encapsulate(self, public_key: bytes) -> Encapsulation:
        raise NotImplementedAlgorithmError(_HINT.format(alg=self.alg_id))

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        raise NotImplementedAlgorithmError(_HINT.format(alg=self.alg_id))
