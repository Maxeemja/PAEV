from dsa import generate_dsa, DSAKeys
from elgamal import generate_eg, EGKeys
from utils import hash_function
from uuid import uuid4, UUID
import random


class Candidate:
    def __init__(self, idd: int):
        self.id = idd
        self.votes = 0


class Voter:
    def __init__(self, name: str):
        self.name = name
        self.id = uuid4()
        self.dsa_keys = generate_dsa()

    def create_vote_message(self, candidate: int, elgamal_public: EGKeys.public):
        # TODO encrypt and sign
        hashed_message = hash_function(bytes(candidate))
        encrypted_message = 0
        signature = 0
        return signature, encrypted_message, self.id


class CEC:
    candidates = [
        Candidate(0),
        Candidate(1),
        Candidate(2),
    ]

    def __init__(self, anon_voters: dict[UUID, DSAKeys.public]):
        self.voters = anon_voters
        self.elgamal_keys = generate_eg()

    def register_vote(self, signature, encrypted_message, voter_id: UUID):
        voter_dsa_public = self.voters.get(voter_id)
        if voter_dsa_public is None:
            print(f"{voter_id} немає права голосувати")
            return
        # TODO: verify and decrypt
        decrypted = 0
        for candidate in CEC.candidates:
            h = hash_function(bytes(candidate.id))
            if h == decrypted:
                candidate.votes += 1
                # TODO додати в список хто за кого проголосував
                del self.voters[voter_id]
                break
        else:
            print(f"{voter_id} відіслав невірний голос, кандидата не існує")

    def results(self):
        for candidate in CEC.candidates:
            print(f"За кандидата {candidate.id} проголосували {candidate.votes} виборців")


class Registrar:
    def __init__(self, voters: list[Voter]):
        self.voters = voters

    def get_anon_voters(self):
        return dict((voter.id, voter.dsa_keys.public) for voter in self.voters)


def main():
    v1 = Voter("Denys")
    v2 = Voter("Maksym")
    v3 = Voter("Ivan")
    v4 = Voter("Taras")
    voters_list = [v1, v2, v3, v4]

    registrar = Registrar(voters_list)
    cec = CEC(registrar.get_anon_voters())
    cec_public_key = cec.elgamal_keys.public

    s, m, n = v1.create_vote_message(0, cec_public_key)
    cec.register_vote(s, m, n)


if __name__ == '__main__':
    main()
