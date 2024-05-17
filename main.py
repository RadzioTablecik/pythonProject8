def rc4(key: bytes, data: bytes) -> bytes:
    # KSA
    s = list(range(256))
    j = 0
    key_length = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % key_length]) % 256
        s[i], s[j] = s[j], s[i]

    # PRGA
    i = j = 0
    ciphertext = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        ciphertext.append(byte ^ k)
    return bytes(ciphertext)

def uses_same_key(ciphertext0: bytes, ciphertext1: bytes) -> bool:
    for i in range(min(len(ciphertext0), len(ciphertext1))):
        if (ciphertext0[i] ^ ciphertext1[i]) >= 0x80:
            return False
    return True

import random
from itertools import combinations

def gen_bank_numbers(q):
    bank_numbers = []
    numery_rozliczeniowe = [
        [1, 0, 1, 0, 0, 0, 0, 0], # NBP
        [1, 1, 6, 0, 0, 0, 0, 6], # Millenium
        [1, 0, 5, 0, 0, 0, 0, 2], # ING
        [2, 1, 2, 0, 0, 0, 0, 1], # Santander
        [1, 0, 2, 0, 0, 0, 0, 3], # PKO BP
    ]
    random.seed(2137)
    for nr in numery_rozliczeniowe:
        for _ in range(q):
            bank_number = ""
            client_number = [random.randint(0, 9) for _ in range(16)]
            tmp = 212500
            for i in range(8):
                tmp += nr[i] * 10 ** (7 - i + 21)
            for i in range(16):
                tmp += client_number[i] * 10 ** (15 - i + 5)
            tmp = tmp % 97
            tmp = 98 - tmp
            bank_number += f"{tmp:02}"
            for i in range(8):
                bank_number += str(nr[i])
            for i in range(16):
                bank_number += str(client_number[i])
            bank_numbers.append(bank_number)
    return bank_numbers

def calculte_nr_control_number(nr):
    weights = [3, 9, 7, 1, 3, 9, 7]
    sum = 0
    for i in range(7):
        sum += nr[i] * weights[i]
    return (10 - (sum % 10)) % 10


def main():
    bank_numbers = gen_bank_numbers(10)
    key = b"Very Good Key"
    cryptograms = []
    for bank_number in bank_numbers:
        cryptogram = rc4(key, bank_number.encode())
        cryptograms.append(cryptogram)

    for c0, c1 in combinations(cryptograms, 2):
        xored = [i0 ^ i1 for i0, i1 in zip(c0, c1)]
        print(xored[2:10])

key = b"Very Good Key"
data = b"Hello, World!"

ciphertext = rc4(key, data)
print("Ciphertext:", ciphertext)
ciphertext = rc4(key, data)
print("Ciphertext:", ciphertext)

decrypted = rc4(key, ciphertext)
print("Decrypted:", decrypted)

ciphertext1 = rc4(key, b"Another message")
ciphertext2 = rc4(b"Different Key", b"Another message")

print("Same key used:", uses_same_key(ciphertext, ciphertext1))
print("Same key used:", uses_same_key(ciphertext, ciphertext2))
