"""Algorithm registry — selecting an algorithm is a lookup by alg_id (data, not code)."""

from __future__ import annotations

from . import classical, pqc
from .errors import UnknownAlgorithmError


class Registry:
    def __init__(self) -> None:
        self._sig: dict[str, object] = {}
        self._kem: dict[str, object] = {}

    def register_signature(self, provider) -> None:
        self._sig[provider.alg_id] = provider

    def register_kem(self, provider) -> None:
        self._kem[provider.alg_id] = provider

    def signature(self, alg_id: str):
        try:
            return self._sig[alg_id]
        except KeyError as e:
            raise UnknownAlgorithmError(f"no signature provider for alg_id {alg_id!r}") from e

    def kem(self, alg_id: str):
        try:
            return self._kem[alg_id]
        except KeyError as e:
            raise UnknownAlgorithmError(f"no KEM provider for alg_id {alg_id!r}") from e

    def signature_algorithms(self) -> tuple[str, ...]:
        return tuple(self._sig)

    def kem_algorithms(self) -> tuple[str, ...]:
        return tuple(self._kem)


def default_registry() -> Registry:
    r = Registry()
    r.register_signature(classical.Ed25519SignatureProvider())
    r.register_signature(pqc.MLDSA65SignatureProvider())
    r.register_kem(classical.X25519KemProvider())
    r.register_kem(pqc.MLKEM768KemProvider())
    return r
