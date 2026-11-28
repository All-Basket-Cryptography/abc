"""Common byte admission for the provider-backed Python profiles."""

def view(value):
    return value if type(value) is bytes else memoryview(value).cast("B")


def fixed(value, length: int) -> bytes:
    wire = view(value)
    if len(wire) != length:
        raise ValueError(f"Expected a {length}-byte input")
    return bytes(wire)


def snapshot(value) -> bytes:
    return bytes(view(value))
