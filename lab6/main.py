from bbs import generate_bbs_keys, BBSKeys, bbs_encrypt, bbs_decrypt
from utils import eg_encrypt, eg_decrypt
from uuid import uuid4, UUID


class Candidate:
    def __init__(self, idd: int):
        self.id = idd
        self.votes = 0


class Voter:
    def __init__(self, name: str):
        self.name = name
        self.token = None

    def create_vote(self, candidate: int):
        e1 = bbs_encrypt(candidate, BBSKeys(self.token[1], self.token[2]))
        return e1, self.token[2], self.token[0]  # E1(M), x0, ID


class EC:
    candidates = [
        Candidate(8),
        Candidate(9),
        Candidate(10),
    ]

    def __init__(self, voters_ids: list[UUID]):
        self.voters = dict()
        for i in voters_ids:
            self.voters[i] = generate_bbs_keys()

    def get_tokens(self):
        return [(voter_id, keys.public, keys.seed) for voter_id, keys in self.voters.items()]

    def register_vote(self, candidate: int, seed: int, idd: UUID):
        if idd not in self.voters:
            print(idd, 'Немає права голосувати або вже проголосував')
            return
        candidate = bbs_decrypt(candidate, BBSKeys(self.voters[idd].public, self.voters[idd].seed))
        for c in EC.candidates:
            if candidate == c.id:
                c.votes += 1
                break
        else:
            print(idd, "Такого кандидата не існує")

    def results(self):
        for candidate in EC.candidates:
            print(f"За кандидата {candidate.id} проголосували {candidate.votes} виборців")


class Registrar:
    def __init__(self, potential_voters: int):
        self.voter_ids = []
        for _ in range(potential_voters):
            self.voter_ids.append(uuid4())
        self.tokens = []
        self.voters = []

    def voter_registration(self, voters: list[Voter]):
        for voter, token in zip(voters, self.tokens):
            voter.token = token
            self.voters.append(voter)
        return self.voters


def main():
    v1 = Voter("Denys")
    v2 = Voter("Maksym")
    v3 = Voter("Ivan")
    v4 = Voter("Taras")
    v5 = Voter("Danylo")

    # Підготовка
    r = Registrar(6)
    ec = EC(r.voter_ids)
    r.tokens = ec.get_tokens()

    # Реєстрація
    voters_list = [v1, v2, v3, v4]
    voters_list = r.voter_registration(voters_list)

    # Голосування
    for voter in voters_list:
        try:
            msg = voter.create_vote(int(input(f"{voter.name} голосує за: ")))
        except Exception:
            print("Введіть ціле число")
        ec.register_vote(*msg)

    # Підрахунок голосів
    ec.results()


if __name__ == '__main__':
    main()
