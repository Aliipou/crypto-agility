import unittest

from crypto_agility import (
    NotImplementedAlgorithmError,
    UnknownAlgorithmError,
    default_registry,
    negotiate,
)
from crypto_agility.classical import Ed25519SignatureProvider, X25519KemProvider


class TestClassicalSignatures(unittest.TestCase):
    def test_ed25519_sign_verify_roundtrip(self):
        p = Ed25519SignatureProvider()
        kp = p.generate_keypair()
        sig = p.sign(kp.private_key, b"hello")
        self.assertTrue(p.verify(kp.public_key, b"hello", sig))

    def test_ed25519_tamper_fails(self):
        p = Ed25519SignatureProvider()
        kp = p.generate_keypair()
        sig = p.sign(kp.private_key, b"hello")
        self.assertFalse(p.verify(kp.public_key, b"HELLO", sig))           # changed message
        self.assertFalse(p.verify(kp.public_key, b"hello", sig[:-1] + bytes([sig[-1] ^ 1])))


class TestClassicalKem(unittest.TestCase):
    def test_x25519_both_sides_agree(self):
        kem = X25519KemProvider()
        recipient = kem.generate_keypair()
        enc = kem.encapsulate(recipient.public_key)
        recovered = kem.decapsulate(recipient.private_key, enc.ciphertext)
        self.assertEqual(enc.shared_secret, recovered)
        self.assertEqual(len(enc.shared_secret), 32)


class TestRegistry(unittest.TestCase):
    def test_lookup_known(self):
        r = default_registry()
        self.assertEqual(r.signature("Ed25519").alg_id, "Ed25519")
        self.assertIn("ML-DSA-65", r.signature_algorithms())
        self.assertIn("X25519", r.kem_algorithms())

    def test_unknown_alg_rejected(self):
        with self.assertRaises(UnknownAlgorithmError):
            default_registry().signature("Ed99999")

    def test_pqc_slot_is_selectable_but_unimplemented(self):
        r = default_registry()
        provider = r.signature("ML-DSA-65")          # selectable
        with self.assertRaises(NotImplementedAlgorithmError):  # but honest about no backend
            provider.generate_keypair()


class TestNegotiation(unittest.TestCase):
    def test_picks_strongest_mutual(self):
        chosen = negotiate(["Ed25519", "Ed25519+ML-DSA-65"], ["Ed25519+ML-DSA-65", "Ed25519"])
        self.assertEqual(chosen, "Ed25519+ML-DSA-65")  # hybrid beats classical


if __name__ == "__main__":
    unittest.main()
