from Crypto.PublicKey import ElGamal
from os import urandom
from typing import NamedTuple, Any
from random import randrange


class EGKeys(NamedTuple):
    private: Any
    public: Any


def generate_eg():
    private = ElGamal.generate(bits=256, randfunc=urandom)
    public = private.publickey()
    return EGKeys(private, public)


def eg_encrypt(msg: int, public: EGKeys.public):
    k = randrange(2, public.p-1)
    a = pow(public.g, k, public.p)
    b = pow(public.y, k) * msg % public.p
    return a, b


def eg_decrypt(a: int, b: int, private: EGKeys.private):
    msg = b*pow(a, private.x)**-1 % private.p
    return msg
