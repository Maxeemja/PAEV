from rsa import generate_rsa, rsa_sign, rsa_verify, Keys
from xor_cipher import generate_sym_key, sym_cipher
from utils import hash_function


class Candidate:
    def __init__(self, idd):
        self.id = idd
        self.votes = 0


class Voter:
    def __init__(self, name):
        self.name = name
        self.symmetric_key = generate_sym_key()
        self.rsa_keys = generate_rsa()

    def create_vote_message(self, candidate: int):
        hashed_message = hash_function(bytes(candidate))
        encrypted_message = sym_cipher(hashed_message, self.symmetric_key)
        signed_encrypted_message = rsa_sign(encrypted_message, self.rsa_keys.private_key)
        return signed_encrypted_message, self.rsa_keys.public_key


class VD:
    candidates = [
        Candidate(0),
        Candidate(1),
        Candidate(2),
    ]

    def __init__(self, voters: list[Voter]):
        self.voters = voters

    def vote(self, signature, public_key: Keys.public_key):
        for voter in self.voters:
            if voter.rsa_keys.public_key == public_key:
                verified = rsa_verify(signature, public_key)
                decrypted = sym_cipher(verified, voter.symmetric_key)
                for candidate in VD.candidates:
                    h = hash_function(bytes(candidate.id))
                    if h == decrypted:
                        candidate.votes += 1
                        self.voters.remove(voter)
                        print(f'{voter.name} проголосував за кандидата {candidate.id}')
                        break
                else:
                    print(f"{voter.name} відіслав невірний голос, кандидата не існує")
                break
        else:
            print("Невідомий публічний ключ, виборець не має права голосувати або вже проголосував")

    def results(self):
        for candidate in VD.candidates:
            print(f"За кандидата {candidate.id} проголосували {candidate.votes} виборців")


def main():
    voter1 = Voter("Denys")
    voter2 = Voter("Maksym")
    voter3 = Voter("Ivan")
    voter4 = Voter("Taras")
    vd = VD([voter1, voter2, voter3, voter4])

    # valid
    print(f'{voter1.name}:')
    msg, pub_key = voter1.create_vote_message(0)
    vd.vote(msg, pub_key)
    print()

    # valid
    print(f'{voter2.name}:')
    msg, pub_key = voter2.create_vote_message(2)
    vd.vote(msg, pub_key)
    print()

    # same person vote again
    print(f'{voter2.name}:')
    vd.vote(msg, pub_key)
    print()

    # invalid candidate
    print(f'{voter3.name}:')
    msg, pub_key = voter3.create_vote_message(5)
    vd.vote(msg, pub_key)
    print()

    # unregistered voter
    print(f'{voter4.name}:')
    msg, pub_key = voter4.create_vote_message(0)
    vd.vote(msg, pub_key)
    print()

    # results
    vd.results()


if __name__ == '__main__':
    main()
