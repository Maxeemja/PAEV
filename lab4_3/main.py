
import math

# Hash function
def hash_func(m):
    hash_val = 0
    while m:
        hash_val += m
        hash_val *= 2
        m //= 10
    return hash_val

# (H^power)mod(n)
def power_and_mod(H, power, n):
    if power == 0:
        return 1
    temp = power_and_mod(H, power // 2, n)
    if power % 2 == 0:
        return temp * temp % n
    else:
        return (((temp * H) % n) * temp) % n

# Inverse modulo
def inverse(a, b):
    for i in range(1, b):
        if (a * i) % b == 1:
            return i
    return 0

# RSA encryption
def rsa_enc(m, e, n):
    return power_and_mod(m, e, n)

# RSA Decryption
def rsa_dec(c, d, n):
    return power_and_mod(c, d, n)

# ElGamal signature
def elgamal_sign(M, g, x, p):
    k = 7
    r = power_and_mod(g, k, p)
    m = hash_func(M)
    s = ((m - x * r) * inverse(k, p - 1)) % (p - 1)
    return [r, s]

# ElGamal signature verification
def elgamal_sign_check(M, y, g, p, rs):
    m = hash_func(M)
    r, s = rs
    return ((power_and_mod(y, r, p) * power_and_mod(r, s, p)) % p == power_and_mod(g, m, p))

class Voter:
    def __init__(self, name):
        # RSA keys
        self.p = 179
        self.q = 23
        self.n = self.p * self.q
        self.e = 7
        self.d = 1119

        # El-Gamal keys
        self.pp = 31
        self.g = 17
        self.x = 3
        self.y = power_and_mod(self.g, self.x, self.pp)
        self.k = 7

        # Stored message at different stages of encryption
        self.my_before = None
        self.my_mes = set()
        self.my_mes_before = set()

        # Random string
        self.rand = 1

        # Voter's name
        self.name = name

    # Getters
    def get_name(self):
        return self.name

    def get_rsa_key(self):
        return [self.e, self.n]

    def get_elgamal_key(self):
        return [self.pp, self.g, self.y]

    def get_my_before(self):
        return self.my_before

    def get_rand(self):
        return self.rand

    # Setters
    def add_mes(self, mes):
        self.my_mes.add(mes)

    def add_mes_before(self, mes):
        self.my_mes_before.add(mes)

    def set_my_before(self, num):
        self.my_before = num

    # Decrypt, verify, and remove random string
    def decrypt_and_check(self, pack):
        found = False
        for i in pack:
            if i[0][0] in self.my_mes:
                found = True
                break
        if not found:
            print(f"\n{self.name} can't find his message between others! {len(self.my_mes)}\n")
            return -1

        for i in pack:
            i[0][0] = rsa_dec(i[0][0], self.d, self.n) - i[1].pop()

        return 1

    # Decrypt and sign
    def decrypt_and_sign(self, with_sign):
        for i in with_sign:
            i[0] = rsa_dec(i[0], self.d, self.n)
            rs = elgamal_sign(i[0], self.g, self.x, self.pp)
            i[1] = rs[0]
            i[2] = rs[1]

    # Check signature
    def check_sign(self, with_sign, voter):
        keys = voter.get_elgamal_key()
        for i in with_sign:
            if not elgamal_sign_check(i[0], keys[2], keys[1], keys[0], [i[1], i[2]]):
                return False
        return True

# Voting procedure
def vote(voter, voter_list, voters, candidates):
    name = voter.get_name()
    print(f"* {name} trying to vote.")

    # Voter's poll
    print("Candidates list:")
    for i in range(len(candidates)):
        print(f"{i + 1}. {candidates[i]} []")

    while True:
        try:
            temp = int(input("I want to vote for (write a number):"))
            if 1 <= temp <= len(candidates):
                break
            else:
                print("Error occurred! Try again")
        except ValueError:
            print("Error occurred! Try again")

    print(f"You, {name}, voted for: {temp}. {candidates[temp - 1]}\n")

    # Ballot formation
    rand = voter.get_rand()
    message = temp + rand
    voter.set_my_before(message)

    # Ballot encryption
    for i in range(len(voter_list) - 1, -1, -1):
        message = rsa_enc(message, voter_list[i].get_rsa_key()[0], voter_list[i].get_rsa_key()[1])
        voter.add_mes_before(message)

    rand_num = 2
    nums = []
    for i in range(len(voter_list) - 1, -1, -1):
        nums.append(rand_num)
        message = rsa_enc(message + rand_num, voter_list[i].get_rsa_key()[0], voter_list[i].get_rsa_key()[1])
        voter.add_mes(message)

    return [[message], nums]

# Tallying the results of the vote
def end_vote(mes, candidates):
    votes = [0] * len(candidates)
    for i in mes:
        votes[i[0] - 1] += 1

    print("Results:")
    for i in range(len(candidates)):
        print(f"{candidates[i]} : {votes[i]}")

if __name__ == "__main__":
    # Forming a list of voters and candidates
    voters = ["Oleksandr Zaytsev", "Pavlo Danylov", "Stepan Giga", "Oleg Gleb"]
    candidates = ["Ivan Ivanenko", "Stepan Stepanenko"]

    A = Voter("Oleksandr Zaytsev")
    B = Voter("Pavlo Danylov")
    F = Voter("Pavlo Danylov")
    C = Voter("Stepan Giga")
    D = Voter("Oleg Gleb")
    E = Voter("Stepan Iga")

    # Forming a list of voters
    voter_list = [A, B, F, C, D, E]

    # Checking the list of voters

    # Checking the list of voters
    voters_seen = set()
    new_voter_list = []
    for i in range(len(voter_list)):
        if (voter_list[i].get_name() not in voters) or (voter_list[i].get_name() in voters_seen):
            print(f"{voter_list[i].get_name()} can't vote or is trying to get in the list again!")
        else:
            new_voter_list.append(voter_list[i])
            voters_seen.add(voter_list[i].get_name())

    # Update the voter_list
    voter_list = new_voter_list

    # Voter polling procedure, encryption of the ballot
    enc_mes = [vote(v, voter_list, voters, candidates) for v in voter_list]

    # Decryption, verification, and removal of the random string
    for vot in voter_list:
        res = vot.decrypt_and_check(enc_mes)
        if res == -1:
            print("\nSomeone changed the message!\n")
            exit(-1)

    # Refactoring the ballot package
    with_sign = [[i[0][0], -1, -1] for i in enc_mes]

    # Decryption and signing
    for i in range(len(voter_list)):
        voter_list[i].decrypt_and_sign(with_sign)
        if 0 < i < len(voter_list) - 1:
            # Signature check
            if not voter_list[i].check_sign(with_sign, voter_list[i - 1]):
                print("Wrong sign!")
                exit(-1)

    # Removal of the random string from decrypted ballots
    for vot in voter_list:
        for j in with_sign:
            if j[0] == vot.get_my_before():
                j[0] -= vot.get_rand()
                break

    # Results
    end_vote(with_sign, candidates)