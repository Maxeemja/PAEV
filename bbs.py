from typing import NamedTuple
from math import pow


class BBSKeys(NamedTuple):
    public: int
    seed: int
    private: tuple[int, int] | None = None


def generate_bbs_keys():
    p = 11
    q = 23
    seed = 3
    return BBSKeys(public=p*q, private=(p, q), seed=seed)


def bbs_bit_sequence(keys: BBSKeys, length: int) -> int:
    x = keys.seed
    result = 0
    for _ in range(length):
        x = x**2 % keys.public
        result = result << 1 | (x & 1)
    return result


def bbs_encrypt(message: int, keys: BBSKeys):
    return message ^ bbs_bit_sequence(keys=keys, length=message.bit_length())


def bbs_decrypt(message: int, keys: BBSKeys):
    return message ^ bbs_bit_sequence(keys=keys, length=4)
