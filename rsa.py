import random
from utils import is_prime, d_finder
from math import gcd
from typing import NamedTuple
from Crypto.PublicKey import RSA


class Keys(NamedTuple):
    public_key: tuple[int, int]
    private_key: tuple[int, int]


# def generate_rsa() -> Keys:
#     primes = [i for i in range(3, 100) if is_prime(i)]
#     p = random.choice(primes)
#     q = random.choice(primes)
#     n = p * q
#     phi = (p-1)*(q-1)
#     e = 2
#     while e < phi:
#         if gcd(e, phi) == 1:
#             break
#         else:
#             e += 1
#     d = d_finder(e, phi)
#     public = (e, n)
#     private = (d, n)
#     return Keys(public, private)


def generate_rsa():
    key_pair = RSA.generate(bits=1024)
    public = key_pair.e, key_pair.n
    private = key_pair.d, key_pair.n
    return Keys(public, private)


def rsa_decrypt(message: bytes, private: Keys.private_key) -> bytes:
    message = int.from_bytes(message)
    decrypted_message = pow(message, private[0], private[1])
    decrypted_message = decrypted_message.to_bytes(128)
    return decrypted_message


def rsa_sign(message: bytes, private: Keys.private_key) -> bytes:
    message = int.from_bytes(message)
    signature = pow(message, private[0], private[1])
    signature = signature.to_bytes(128)
    return signature


def rsa_encrypt(message: bytes, public: Keys.public_key) -> bytes:
    message = int.from_bytes(message)
    encrypted_message = pow(message, public[0], public[1])
    encrypted_message = encrypted_message.to_bytes(32)
    return encrypted_message


def rsa_verify(signature: bytes, public: Keys.public_key) -> bytes:
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
