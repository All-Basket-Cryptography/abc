"""RFC 5869 extraction and expansion with the ABC Python HMAC core."""

from importlib import import_module


_hmac = import_module("src.crypto.mac.hmac-sha256.impl.python.abc_hmac_sha256")
TAG_BYTES = 32
MAX_OUTPUT_BYTES = 255 * TAG_BYTES


def extract(salt, input_key_material) -> bytes:
    """Derive a 32-byte PRK. None represents an omitted salt."""
    return _hmac.authenticate(bytes(TAG_BYTES) if salt is None else salt, input_key_material)


def expand(prk, info, output_length: int) -> bytes:
    """Derive up to 8,160 bytes from a PRK of at least 32 bytes."""
    key, context = _hmac.byte_view(prk), _hmac.byte_view(info)
    if not TAG_BYTES <= len(key) <= _hmac.MAX_MESSAGE_BYTES:
        raise ValueError("HKDF PRK length must be at least 32 bytes and fit HMAC")
    if type(output_length) is not int or not 0 <= output_length <= MAX_OUTPUT_BYTES:
        raise ValueError("HKDF output length must be an integer from 0 through 8160")
    if output_length == 0:
        return b""
    overhead = TAG_BYTES + 1 if output_length > TAG_BYTES else 1
    if len(context) > _hmac.MAX_INPUT_BYTES - overhead:
        raise OverflowError("HKDF info exceeds the HMAC message domain")

    output = bytearray()
    previous = b""
    mac = _hmac.HmacSha256(key)
    for counter in range(1, (output_length + TAG_BYTES - 1) // TAG_BYTES + 1):
        if counter > 1:
            mac.reset()
            mac.update(previous)
        mac.update(context)
        mac.update(bytes((counter,)))
        previous = mac.digest()
        output.extend(previous[:output_length - len(output)])
    return bytes(output)


def derive(salt, input_key_material, info, output_length: int) -> bytes:
    """Extract a PRK and then expand it."""
    return expand(extract(salt, input_key_material), info, output_length)
