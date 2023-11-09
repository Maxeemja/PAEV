from Crypto.PublicKey import DSA
from typing import NamedTuple, Any


class DSAKeys(NamedTuple):
    private: Any
    public: Any


def generate_dsa():
    private = DSA.generate(bits=1024)
    public = private.public_key()
    return DSAKeys(private, public)
