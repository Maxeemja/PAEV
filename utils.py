import hashlib
from math import factorial


def hash_function(message: bytes) -> bytes:
    h = hashlib.sha256(message)
    return h.digest()


def is_prime(x):
    return factorial(x - 1) % x == x - 1


def d_finder(e, phi) -> int:
    d = 1
    while e*d % phi != 1:
        d += 1
    return d
