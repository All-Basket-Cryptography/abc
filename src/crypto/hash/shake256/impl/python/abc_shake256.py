"""Byte-oriented SHAKE256 implemented with the ABC Python Keccak core."""

from abc_keccak_p1600 import RATE_BYTES, BytesLike, ShakeReader, Sponge


BLOCK_SIZE = RATE_BYTES


class Shake256:
    """Absorb a message and obtain separate SHAKE256 output readers."""

    def __init__(self) -> None:
        self._sponge = Sponge()

    def update(self, data: BytesLike) -> None:
        self._sponge.update(data)

    def reset(self) -> None:
        self._sponge.reset()

    def finalize(self) -> ShakeReader:
        """Start a separate output reader without consuming this absorber."""
        return self._sponge.shake_reader()


def shake256(data: BytesLike, size: int) -> bytes:
    absorber = Shake256()
    absorber.update(data)
    return absorber.finalize().read(size)
