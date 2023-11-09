from Crypto.PublicKey import ElGamal
from typing import NamedTuple, Any


class EGKeys(NamedTuple):
    private: Any
    public: Any


def generate_eg():
    private = ElGamal.generate(bits=1024)
    public = private.publickey()
    return EGKeys(private, public)
