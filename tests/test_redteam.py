"""Adversarial: the attacker controls negotiation inputs and signatures."""

import hashlib
import unittest

from crypto_agility import AlgorithmStrength, NegotiationError, negotiate
from crypto_agility.classical import Ed25519SignatureProvider
from crypto_agility.hybrid import HybridSignatureProvider, _pack, _unpack
from crypto_agility.interfaces import SignatureKeyPair
from crypto_agility.pqc import MLDSA65SignatureProvider
from crypto_agility.errors import NotImplementedAlgorithmError


class _MockPqcSig:
    """A test double (toy MAC) used ONLY to exercise hybrid LOGIC — not real crypto."""

    alg_id = "MOCK-PQC"

    def generate_keypair(self):
        import os
        seed = os.urandom(8)
        return SignatureKeyPair(self.alg_id, b"pub:" + seed, b"prv:" + seed)

    def sign(self, private_key, message):
        seed = private_key[len(b"prv:"):]
        return hashlib.sha256(b"prv:" + seed + message).digest()

    def verify(self, public_key, message, signature):
        seed = public_key[len(b"pub:"):]
        return signature == hashlib.sha256(b"prv:" + seed + message).digest()


class TestDowngradeStrip(unittest.TestCase):
    def test_stripping_strong_algorithm_fails_closed(self):
        # Attacker removes the hybrid option from the peer's offer, leaving only
        # classical. With a HYBRID floor, negotiation must REFUSE, not downgrade.
        with self.assertRaises(NegotiationError):
            negotiate(
                local_offered=["Ed25519+ML-DSA-65", "Ed25519"],
                peer_offered=["Ed25519"],                      # strong option stripped
                floor=AlgorithmStrength.HYBRID,
            )

    def test_no_mutual_algorithm_fails_closed(self):
        with self.assertRaises(NegotiationError):
            negotiate(["Ed25519"], ["ML-DSA-65"])

    def test_unknown_algorithm_rejected(self):
        with self.assertRaises(NegotiationError):
            negotiate(["forged-alg"], ["forged-alg"])


class TestHybridFailsClosed(unittest.TestCase):
    def test_hybrid_with_real_pqc_slot_refuses_to_degrade(self):
        # Ed25519 + the real (unimplemented) ML-DSA-65 slot: you cannot get a hybrid
        # keypair at all. It does NOT silently fall back to classical-only.
        h = HybridSignatureProvider(Ed25519SignatureProvider(), MLDSA65SignatureProvider())
        with self.assertRaises(NotImplementedAlgorithmError):
            h.generate_keypair()

    def test_hybrid_requires_both_halves(self):
        h = HybridSignatureProvider(Ed25519SignatureProvider(), _MockPqcSig())
        kp = h.generate_keypair()
        sig = h.sign(kp.private_key, b"transfer")
        self.assertTrue(h.verify(kp.public_key, b"transfer", sig))

        c_sig, p_sig = _unpack(sig, 2)
        forged_classical = _pack(c_sig[:-1] + bytes([c_sig[-1] ^ 1]), p_sig)
        forged_pqc = _pack(c_sig, p_sig[:-1] + bytes([p_sig[-1] ^ 1]))
        self.assertFalse(h.verify(kp.public_key, b"transfer", forged_classical))  # one half broken
        self.assertFalse(h.verify(kp.public_key, b"transfer", forged_pqc))        # other half broken


if __name__ == "__main__":
    unittest.main()
