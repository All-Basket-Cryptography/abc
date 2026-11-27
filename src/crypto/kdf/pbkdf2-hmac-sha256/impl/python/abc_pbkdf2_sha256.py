"""RFC 8018 PBKDF2 using the ABC Python HMAC-SHA-256 core."""

from importlib import import_module


_hmac = import_module("src.crypto.mac.hmac-sha256.impl.python.abc_hmac_sha256")
TAG_BYTES = 32
MAX_ITERATIONS = (1 << 32) - 1
MAX_OUTPUT_BYTES = MAX_ITERATIONS * TAG_BYTES


def derive(password, salt, iterations: int, output_length: int) -> bytes:
    """Derive a positive number of bytes with a nonzero 32-bit iteration count."""
    key, salt_bytes = _hmac.byte_view(password), _hmac.byte_view(salt)
    if type(iterations) is not int or not 1 <= iterations <= MAX_ITERATIONS:
        raise ValueError("PBKDF2 iterations must be a positive 32-bit integer")
    if type(output_length) is not int or not 1 <= output_length <= MAX_OUTPUT_BYTES:
        raise ValueError("PBKDF2 output length exceeds its positive block-index domain")
    if len(key) > _hmac.MAX_MESSAGE_BYTES or len(salt_bytes) > _hmac.MAX_INPUT_BYTES - 4:
        raise OverflowError("PBKDF2 password or salt exceeds the HMAC length domain")

    result = bytearray()
    mac = _hmac.HmacSha256(key)
    for index in range(1, (output_length + TAG_BYTES - 1) // TAG_BYTES + 1):
        mac.reset()
        mac.update(salt_bytes)
        mac.update(index.to_bytes(4, "big"))
        previous = mac.digest()
        accumulated = bytearray(previous)
        for _ in range(1, iterations):
            mac.reset()
            mac.update(previous)
            previous = mac.digest()
            for i, byte in enumerate(previous):
                accumulated[i] ^= byte
        result.extend(accumulated[:output_length - len(result)])
    return bytes(result)
