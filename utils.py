import hashlib
from math import factorial
from random import choice


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

def random_divider(n):
    l = []
    for i in range(2, int(n / 2) + 1):
        if n % i == 0:
            l.append(i)
    div1 = choice(l)
    div2 = int(n / div1)
    return div1, div2
