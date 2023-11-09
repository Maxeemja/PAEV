from dsa import generate_dsa, DSAKeys, dsa_sign, dsa_verify
from elgamal import generate_eg, EGKeys
from xor_cipher import sym_cipher, generate_sym_key
from utils import hash_function
from uuid import uuid4, UUID


class Candidate:
    def __init__(self, idd: int):
        self.id = idd
        self.votes = 0


class Voter:
    def __init__(self, name: str):
        self.name = name
        self.id = uuid4()
        self.dsa_keys = generate_dsa()

    def create_vote_message(self, candidate: int, key: bytes):
        hashed_msg = hash_function(bytes(candidate))
        encrypted_msg = sym_cipher(hashed_msg, key)
        signature = dsa_sign(encrypted_msg, self.dsa_keys.private)
        return signature, encrypted_msg, self.id


class CEC:
    candidates = [
        Candidate(0),
        Candidate(1),
        Candidate(2),
    ]

    def __init__(self, anon_voters: dict[UUID, DSAKeys.public]):
        self.voters_to_vote = anon_voters
        self.symmetric_key = generate_sym_key()
        self.result_dict = dict()

    def register_vote(self, signature, encrypted_message, voter_id: UUID):
        if voter_id in self.result_dict:
            print(f"{voter_id} вже проголосував")
            return
        if voter_id not in self.voters_to_vote:
            print(f"{voter_id} немає права голосувати")
            return
        voter_dsa_public = self.voters_to_vote[voter_id]
        try:
            verified_msg = dsa_verify(signature, encrypted_message, voter_dsa_public)
        except ValueError as e:
            print(voter_id, e)
            return
        decrypted_msg = sym_cipher(verified_msg, self.symmetric_key)
        for candidate in CEC.candidates:
            hashed_candidate = hash_function(bytes(candidate.id))
            if hashed_candidate == decrypted_msg:
                candidate.votes += 1
                self.result_dict[voter_id] = candidate.id
                del self.voters_to_vote[voter_id]
                break
        else:
            print(f"{voter_id} відіслав невірний голос, кандидата не існує")

    def results(self):
        for voter_id, candidate_id in self.result_dict.items():
            print(f"Виборець {voter_id} проголосував за кандидата {candidate_id}")
        print()
        for candidate in CEC.candidates:
            print(f"За кандидата {candidate.id} проголосували {candidate.votes} виборців")

        print(f"\n{len(self.voters_to_vote)} виборців не використали своє право голосу")

        return self.result_dict


class Registrar:
    def __init__(self, voters: list[Voter]):
        self.voters = voters

    def get_anon_voters(self):
        return dict((voter.id, voter.dsa_keys.public) for voter in self.voters)

    def verify_results(self, result_dict):
        for voter_id in result_dict:
            if any(voter.id == voter_id for voter in self.voters):
                break
        else:
            print("\nБуло знайдено невідомого виборця в опублікованих списках. Виборча дільниця фальсифікувала голоси")


def main():
    v1 = Voter("Denys")
    v2 = Voter("Maksym")
    v3 = Voter("Ivan")
    v4 = Voter("Taras")
    v5 = Voter("Danylo")
    voters_list = [v1, v2, v3, v4]

    registrar = Registrar(voters_list)
    cec = CEC(registrar.get_anon_voters())
    cec_key = cec.symmetric_key

    # v1
    s, msg, num = v1.create_vote_message(0, cec_key)
    cec.register_vote(s, msg, num)

    # v2
    s, msg, num = v2.create_vote_message(2, cec_key)
    cec.register_vote(s, msg, num)

    # v2 голосує повторно
    s, msg, num = v2.create_vote_message(2, cec_key)
    cec.register_vote(s, msg, num)

    # v3 голосує за неіснуючого кандидата (невірний бюлетень)
    s, msg, num = v3.create_vote_message(9, cec_key)
    cec.register_vote(s, msg, num)

    # v3
    s, msg, num = v3.create_vote_message(0, cec_key)
    cec.register_vote(s, msg, num)

    # v4 намагається проголосувати з невірним signature
    s, msg, num = v4.create_vote_message(9, cec_key)
    cec.register_vote(b'random', msg, num)

    # v5 не зареєстрований
    s, msg, num = v5.create_vote_message(0, cec_key)
    cec.register_vote(s, msg, num)

    print("\n_____ВД публікує результати_____")
    res = cec.results()
    registrar.verify_results(res)


if __name__ == '__main__':
    main()
