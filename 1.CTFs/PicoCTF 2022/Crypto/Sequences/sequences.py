#!/bin/python3
import math
import hashlib
import sys
from tqdm import tqdm
import functools

# extra imports
from mpmath import *
from gmpy2 import *

sys.setrecursionlimit(99999)


ITERS = int(2e7)
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex("42cbbce1487b443de1acf4834baed794f4bbd0dfb5df5e6f2ad8a2c32b")

# This will overflow the stack, it will need to be significantly optimized in order to get the answer :)


@functools.cache
def m_func(i):
    if i == 0: return 1
    if i == 1: return 2
    if i == 2: return 3
    if i == 3: return 4

    sol = 55692*m_func(i-4) - 9549*m_func(i-3) + 301*m_func(i-2) + 21*m_func(i-1)
    return sol

    

def b_func(i): # better func
    # lattice = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
    # lattice[0][3] = 55692
    # lattice[0][2] = -9549
    # lattice[0][1] = 301
    # lattice[0][0] = 21

    # lattice[0][0] = 1
    # lattice[1][0] = 1
    # lattice[2][0] = 1

    

    mp.dps = 1000000000
    den = mpf(42636)
    a = mpf(1612*((-21)**i))
    print("Finished a")
    b = mpf(30685*(2**(2*i + 5))*(3**i))
    print("Finished b")
    c = mpf(1082829*(13**i))
    print("Finished c")
    d = mpf(8349*(17**(i+1)))
    print("Finished d")


    num =  (a + b - c + d)/den
    

    return int(num)



# Decrypt the flag
def decrypt_flag(sol):
    print("Decrypting now")
    sol = sol % (10**10000)
    sol = str(sol)
    sol_md5 = hashlib.md5(sol.encode()).hexdigest()

    if sol_md5 != VERIF_KEY:
        print("Incorrect solution")
        sys.exit(1)

    key = hashlib.sha256(sol.encode()).digest()
    flag = bytearray([char ^ key[i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()

    print(flag)

if __name__ == "__main__":

    # sol = m_func(ITERS)
    # for i in range(ITERS + 1):
    #     if(i == ITERS):
    #         print(m_func(i))
    #     m_func(i)
    #     print(i)
    sol = b_func(ITERS)
    # print(sol)
    # sol = 2.966654489521374075871728605094816945046301072644116288e26444384
    decrypt_flag(sol)
