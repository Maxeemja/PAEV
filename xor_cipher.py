import os


def generate_sym_key() -> bytes:
    return os.urandom(32)


# Both encrypt and decrypt
def sym_cipher(message: bytes, key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(message, key))
