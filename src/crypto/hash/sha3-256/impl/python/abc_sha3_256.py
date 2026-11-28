"""Byte-oriented SHA3-256 implemented with the ABC Python Keccak core."""

from abc_keccak_p1600 import RATE_BYTES, BytesLike, Sponge


DIGEST_SIZE = 32
BLOCK_SIZE = RATE_BYTES


class Sha3_256:
    """Incrementally hash bytes and take non-destructive digest snapshots."""

    def __init__(self) -> None:
        self._sponge = Sponge()

    def update(self, data: BytesLike) -> None:
        self._sponge.update(data)

    def reset(self) -> None:
        self._sponge.reset()

    def digest(self) -> bytes:
        return self._sponge.sha3_digest()


def sha3_256(data: BytesLike) -> bytes:
    hasher = Sha3_256()
    hasher.update(data)
    return hasher.digest()
