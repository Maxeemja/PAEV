from rsa import Keys, generate_rsa, rsa_sign, rsa_verify, rsa_decrypt, rsa_encrypt, rsa_blind, rsa_unblind
from xor_cipher import generate_sym_key, sym_cipher
from utils import hash_function
from uuid import uuid4
from random import randint, choice


class Candidate:
    def __init__(self, idd):
        self.id = idd
        self.votes = 0


class Voter:
    def __init__(self, name):
        self.name = name
        self.id = uuid4()
        self.rsa_keys = generate_rsa()
        self.blind_factor = randint(10, 100)

    def create_collection_of_bulletins(self, cec):
        bulletins_list = []
        for _ in range(10):
            candidates_list = []
            for candidate in cec.candidates:
                blinded_candidate = rsa_blind(candidate.id.to_bytes(32), self.blind_factor)
                candidates_list.append(blinded_candidate)
            bulletins_list.append(candidates_list)
        return bulletins_list, self.id, self.blind_factor

    def create_vote_message(self, signed_blinded_bulletin: list, cec_pub: Keys.public_key):
        signed_bulletin = [rsa_unblind(c, self.blind_factor) for c in signed_blinded_bulletin]
        candidate = choice(signed_bulletin)
        encrypted_message = rsa_encrypt(candidate, cec_pub)
        return encrypted_message


# TODO
def bulletins_valid_check(bulletins: list, blind_factor):
    return True


class CEC:
    candidates = [
        Candidate(0),
        Candidate(1),
        Candidate(2),
    ]

    def __init__(self, voters: list[Voter]):
        self.voters = voters
        self.rsa_keys = generate_rsa()

    def bulletins_proccessing(self, bulletins_list, voter_id, blind_factor):
        for voter in self.voters:
            if voter.id == voter_id:
                choosen_bulletin = choice(bulletins_list)
                bulletins_list.remove(choosen_bulletin)
                if bulletins_valid_check(bulletins_list, blind_factor):
                    return [rsa_sign(candidate, self.rsa_keys.private_key) for candidate in choosen_bulletin]
                else:
                    print("Набір бюлетенів не валідний")
                break
        else:
            print("Невідомий ID, виборець не має права голосувати або вже отримав підписаний бюлетень")

    def receive_vote_message(self, encrypted_signed_msg):
        signed_msg = rsa_decrypt(encrypted_signed_msg, self.rsa_keys.private_key)
        verified_msg = rsa_verify(signed_msg, self.rsa_keys.public_key)
        for c in CEC.candidates:
            if c.id == int.from_bytes(verified_msg):
                c.votes += 1

    @staticmethod
    def results():
        for candidate in CEC.candidates:
            print(f"За кандидата {candidate.id} проголосували {candidate.votes} виборців")


def main():
    voter1 = Voter("Denys")
    voter2 = Voter("Maksym")
    voter3 = Voter("Ivan")
    voter4 = Voter("Taras")
    cec = CEC([voter1, voter2, voter3, voter4])

    bulletins, v_id, blind_factor = voter1.create_collection_of_bulletins(cec)
    random_signed_blinded_bulletin = cec.bulletins_proccessing(bulletins, v_id, blind_factor)
    msg = voter1.create_vote_message(random_signed_blinded_bulletin, cec_pub=cec.rsa_keys.public_key)
    cec.receive_vote_message(msg)

    cec.results()


if __name__ == '__main__':
    main()
