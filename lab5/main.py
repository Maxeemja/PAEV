from dsa import generate_dsa, DSAKeys, dsa_sign, dsa_verify
from rsa import generate_rsa, RSAKeys, rsa_encrypt, rsa_decrypt
from utils import hash_function, random_divider
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

    def create_vote_message(self, candidate: int, *keys: RSAKeys.public_key):
        div1, div2 = random_divider(candidate)
        encrypted_msg1 = rsa_encrypt(div1, keys[0])
        encrypted_msg2 = rsa_encrypt(div2, keys[1])
        signature1 = dsa_sign(encrypted_msg1, self.dsa_keys.private)
        signature2 = dsa_sign(encrypted_msg2, self.dsa_keys.private)
        return signature1, encrypted_msg1, signature2, encrypted_msg2, self.id


class EC:
    def __init__(self, anon_voters: dict[UUID, DSAKeys.public], ph: str):
        self.voters_to_vote = anon_voters
        self.rsa_keys = generate_rsa()
        self.result_dict = dict()
        self.trace_phrase = ph

    def register_vote(self, signature, encrypted_message, voter_id: UUID):
        if voter_id in self.result_dict:
            print(f"{self.trace_phrase}: {voter_id} вже проголосував")
            return
        if voter_id not in self.voters_to_vote:
            print(f"{self.trace_phrase}: {voter_id} немає права голосувати")
            return
        voter_dsa_public = self.voters_to_vote[voter_id]
        try:
            verified_msg = dsa_verify(signature, encrypted_message, voter_dsa_public)
        except ValueError as e:
            print(self.trace_phrase+":", voter_id, e)
            return
        decrypted_divider = rsa_decrypt(verified_msg, self.rsa_keys.private_key)
        self.result_dict[voter_id] = decrypted_divider
        del self.voters_to_vote[voter_id]

    def results(self):
        for voter_id, divider in self.result_dict.items():
            print(f"Виборець {voter_id} відправив {divider}")
        print(f"\n{len(self.voters_to_vote)} виборців не використали своє право голосу")
        return self.result_dict


class CentralEC:
    candidates = [
        Candidate(8),
        Candidate(9),
        Candidate(10),
    ]

    def __init__(self, voters: list[Voter]):
        self.voters = voters

    def get_anon_voters(self):
        return dict((voter.id, voter.dsa_keys.public) for voter in self.voters)

    def calculate_votes(self, d1, d2):
        result = {k: d1.get(k, 0) * d2.get(k, 0) for k in set(d1) & set(d2)}
        for voter_id, candidate in result.items():
            voter_name = (v.name for v in self.voters if v.id == voter_id).__next__()
            if any(c.id == candidate for c in CentralEC.candidates):
                print(f'Виборець {voter_id} ({voter_name}) проголосував за кандидата {candidate}')
            else:
                print(f'Виборець {voter_id} ({voter_name}) проголосував за неіснуючого кандидата: {candidate}')

def main():
    v1 = Voter("Denys")
    v2 = Voter("Maksym")
    v3 = Voter("Ivan")
    v4 = Voter("Taras")
    v5 = Voter("Danylo")
    voters_list = [v1, v2, v3, v4]

    cec = CentralEC(voters_list)
    ec1 = EC(cec.get_anon_voters(), "ВД1")
    ec2 = EC(cec.get_anon_voters(), "ВД2")
    keys = (ec1.rsa_keys.public_key, ec2.rsa_keys.public_key)

    # v1
    s1, msg1, s2, msg2, v_id = v1.create_vote_message(8, *keys)
    ec1.register_vote(s1, msg1, v_id)
    ec2.register_vote(s2, msg2, v_id)
    # v2
    s1, msg1, s2, msg2, v_id = v2.create_vote_message(9, *keys)
    ec1.register_vote(s1, msg1, v_id)
    ec2.register_vote(s2, msg2, v_id)
    # v2 голосує повторно
    s1, msg1, s2, msg2, v_id = v2.create_vote_message(9, *keys)
    ec1.register_vote(s1, msg1, v_id)
    ec2.register_vote(s2, msg2, v_id)
    # v3 голосує за неіснуючого кандидата (невірний бюлетень)
    s1, msg1, s2, msg2, v_id = v3.create_vote_message(12, *keys)
    ec1.register_vote(s1, msg1, v_id)
    ec2.register_vote(s2, msg2, v_id)
    # v4 намагається проголосувати з невірним signature
    s1, msg1, s2, msg2, v_id = v4.create_vote_message(9, *keys)
    ec1.register_vote(b"random", msg1, v_id)
    ec2.register_vote(s2, msg2, v_id)
    # v5 не зареєстрований
    s1, msg1, s2, msg2, v_id = v5.create_vote_message(9, *keys)
    ec1.register_vote(s1, msg1, v_id)
    ec2.register_vote(s2, msg2, v_id)


    print("\n_____ВК1 публікує результати_____")
    res1 = ec1.results()
    print("\n_____ВК2 публікує результати_____")
    res2 = ec2.results()
    print("\n_____ЦВК публікує результати_____")
    cec.calculate_votes(res1, res2)


if __name__ == '__main__':
    main()
