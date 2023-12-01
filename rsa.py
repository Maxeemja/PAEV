from typing import NamedTuple
from Crypto.PublicKey import RSA


class RSAKeys(NamedTuple):
    public_key: tuple[int, int]
    private_key: tuple[int, int]


def generate_rsa():
    key_pair = RSA.generate(bits=1024)
    public = key_pair.e, key_pair.n
    private = key_pair.d, key_pair.n
    return RSAKeys(public, private)


def rsa_decrypt(message: int, private: RSAKeys.private_key) -> bytes:
    decrypted_message = pow(message, private[0], private[1])
    return decrypted_message


def rsa_sign(message: bytes, private: RSAKeys.private_key) -> bytes:
    message = int.from_bytes(message)
    signature = pow(message, private[0], private[1])
    signature = signature.to_bytes(128)
    return signature


def rsa_encrypt(message: int, public: RSAKeys.public_key) -> bytes:
    encrypted_message = pow(message, public[0], public[1])
    return encrypted_message


def rsa_verify(signature: bytes, public: RSAKeys.public_key) -> bytes:
    signature = int.from_bytes(signature)
    message = pow(signature, public[0], public[1])
    message = message.to_bytes(32)
    return message


def rsa_blind(message: bytes, blind_factor: int):
    blinded_message = message
    return blinded_message


def rsa_unblind(blinded_signature: bytes, blind_factor: int):
    signature = blinded_signature
    return signature
