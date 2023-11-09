from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from typing import NamedTuple, Any


class DSAKeys(NamedTuple):
    private: Any
    public: Any


def generate_dsa():
    private = DSA.generate(bits=2048)
    public = private.public_key()
    return DSAKeys(private, public)


def dsa_sign(msg, private: DSAKeys.private):
    hash_obj = SHA256.new(msg)
    signer = DSS.new(private, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature


# wrap with try except (ValueError)
def dsa_verify(signature, msg, public: DSAKeys.public):
    hash_obj = SHA256.new(msg)
    verifier = DSS.new(public, 'fips-186-3')
    verifier.verify(hash_obj, signature)
    return msg
