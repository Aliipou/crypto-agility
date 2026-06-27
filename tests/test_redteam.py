"""Adversarial: the attacker controls negotiation inputs and signatures."""

import hashlib
import unittest

from crypto_agility import (
    AlgorithmStrength,
    NegotiationError,
    negotiate,
    negotiate_authenticated,
    sign_offer,
)
from crypto_agility.classical import Ed25519SignatureProvider
from crypto_agility.hybrid import HybridSignatureProvider, _pack, _unpack
from crypto_agility.interfaces import SignatureKeyPair
from crypto_agility.pqc import MLDSA65SignatureProvider
from crypto_agility.errors import NotImplementedAlgorithmError, VerificationError


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


class TestAuthenticatedNegotiation(unittest.TestCase):
    """Bind negotiation to a signed offer so an active MITM can't rewrite the offer.

    The unauthenticated ``negotiate`` trusts both offered sets: a MITM that rewrites
    BOTH sides moves the negotiation below the floor undetected. ``negotiate_authenticated``
    verifies the peer's Ed25519 signature over the offered set *before* selecting.
    """

    def setUp(self):
        self.ed = Ed25519SignatureProvider()
        self.peer_kp = self.ed.generate_keypair()
        self.nonce = b"exchange-nonce-0001"
        # Honest peer offers the strong (hybrid) set and signs exactly that.
        self.peer_offered = ["Ed25519+ML-DSA-65", "Ed25519"]
        self.peer_sig = sign_offer(self.peer_offered, self.nonce, self.peer_kp.private_key)
        self.local_offered = ["Ed25519+ML-DSA-65", "Ed25519"]

    def test_happy_path_signed_offer_picks_strongest_mutual(self):
        chosen = negotiate_authenticated(
            self.local_offered, self.peer_offered, self.peer_sig,
            self.peer_kp.public_key,
            floor=AlgorithmStrength.HYBRID, nonce=self.nonce,
        )
        self.assertEqual(chosen, "Ed25519+ML-DSA-65")

    def test_active_mitm_rewrite_to_weaker_set_is_rejected(self):
        # Attacker strips the hybrid option from the offered set on the wire, trying to
        # force a classical downgrade. The peer's signature was over the STRONG set, so
        # it no longer matches the rewritten weaker set -> verify fails -> refuse.
        rewritten = ["Ed25519"]                       # strong option stripped by MITM
        with self.assertRaises(VerificationError):
            negotiate_authenticated(
                self.local_offered, rewritten, self.peer_sig,
                self.peer_kp.public_key,
                floor=AlgorithmStrength.HYBRID, nonce=self.nonce,
            )

    def test_attacker_cannot_forge_signature_over_rewritten_set(self):
        # The attacker has no peer private key, so any signature they produce over the
        # weaker set is under their OWN key, not the peer's pinned key -> rejected.
        mitm_kp = self.ed.generate_keypair()
        rewritten = ["Ed25519"]
        mitm_sig = sign_offer(rewritten, self.nonce, mitm_kp.private_key)
        with self.assertRaises(VerificationError):
            negotiate_authenticated(
                self.local_offered, rewritten, mitm_sig,
                self.peer_kp.public_key,                 # still verifying against the PEER key
                floor=AlgorithmStrength.HYBRID, nonce=self.nonce,
            )

    def test_tampered_signature_byte_is_rejected(self):
        bad_sig = self.peer_sig[:-1] + bytes([self.peer_sig[-1] ^ 1])
        with self.assertRaises(VerificationError):
            negotiate_authenticated(
                self.local_offered, self.peer_offered, bad_sig,
                self.peer_kp.public_key,
                floor=AlgorithmStrength.HYBRID, nonce=self.nonce,
            )

    def test_nonce_mismatch_breaks_binding(self):
        # A signature is bound to its nonce; verifying under a different nonce fails.
        with self.assertRaises(VerificationError):
            negotiate_authenticated(
                self.local_offered, self.peer_offered, self.peer_sig,
                self.peer_kp.public_key,
                floor=AlgorithmStrength.HYBRID, nonce=b"different-nonce",
            )

    def test_replay_with_stale_nonce_rejected_when_freshness_tracked(self):
        seen = set()
        first = negotiate_authenticated(
            self.local_offered, self.peer_offered, self.peer_sig,
            self.peer_kp.public_key,
            floor=AlgorithmStrength.HYBRID, nonce=self.nonce, seen_nonces=seen,
        )
        self.assertEqual(first, "Ed25519+ML-DSA-65")
        # Replaying the exact same signed offer (valid sig!) is now stale -> rejected.
        with self.assertRaises(NegotiationError):
            negotiate_authenticated(
                self.local_offered, self.peer_offered, self.peer_sig,
                self.peer_kp.public_key,
                floor=AlgorithmStrength.HYBRID, nonce=self.nonce, seen_nonces=seen,
            )

    def test_canonical_encoding_is_injective_across_split_boundaries(self):
        from crypto_agility.negotiation import canonical_offer
        # Length-prefixing must keep ["A","BC"] and ["AB","C"] distinct.
        self.assertNotEqual(
            canonical_offer(["A", "BC"], self.nonce),
            canonical_offer(["AB", "C"], self.nonce),
        )
        # Order/duplication carry no meaning: same canonical bytes either way.
        self.assertEqual(
            canonical_offer(["Ed25519", "Ed25519+ML-DSA-65"], self.nonce),
            canonical_offer(["Ed25519+ML-DSA-65", "Ed25519", "Ed25519"], self.nonce),
        )


if __name__ == "__main__":
    unittest.main()
