#!/bin/python3
from math import ceil, sqrt, gcd, lcm
import random
import time
from gmpy2 import mpz
from factordb.factordb import FactorDB
from functools import reduce
from Crypto.Util.number import *


def pollard(n):
    a = 2
    b = 2
    while True:
        a = pow(a,b,n)
        d = gcd(a-1,n)
        if 1 < d < n: 
            return d
        b += 1

def getFactors(n):
    a = n // 2
    b = pollard(a)
    c = a // b
    factors = [2,b]
    while(not isPrime(c)):
        fac = pollard(c)
        factors.append(fac)
        c = c // fac
    factors.append(c)

    # idk, im dumb
    newFactors = []
    for n in factors:
        if isPrime(n):
            newFactors.append(n)
        else:
            f = FactorDB(n)
            f.connect()
            newFactors.extend(f.get_factor_list())

    powFac = [(i, 1) for i in newFactors]
    return powFac

def bsgs(g, h, p, upper_bound=None):
    if upper_bound:
        m = ceil(sqrt(upper_bound))
    else:
        m = ceil(sqrt(p-1))

    if not hasattr(bsgs, 'baby_steps'):
        bsgs.baby_steps = dict()
        gi = mpz(1)
        for i in range(m):
            bsgs.baby_steps[gi] = i
            gi = (gi * g) % p

    c = pow(g, m * (p - 2), p)
    hi = h
    # giant steps
    for j in range(m):
        if hi in bsgs.baby_steps:
            return j * m + bsgs.baby_steps[hi]
        hi = (hi * c) % p
    # No solution
    return None

def crt(xs, ns_fac, n):
    x = 0
    ns = [p**e for p,e in ns_fac]
    common = gcd(*ns)
    ns = [n // common for n in ns]

    for xi, ni in zip(xs, ns):
        yi = n // ni
        zi = pow(yi, -1, ni)
        x += xi * yi * zi
    return x % n

def pohlig_hellman(g,h,p,n,n_factors):
    dlogs = []
    for pi, ei in n_factors:
        # Set up for each step
        ni = pi**ei
        gi = pow(g, n // ni, p)
        hi = pow(h, n // ni, p)

        # Groups of prime-power order
        xi = 0
        hk_exp = ni // pi
        gamma = pow(gi, hk_exp, p)

        for k in range(ei):
            # Create hk in <γ>
            gk = pow(gi, -xi, p)
            hk = pow(gk*hi, hk_exp, p)
            # make call to rust
            dk = bsgs(gamma, hk, p, upper_bound=pi)
            # increment the secret
            xi += dk*(pi**k)
            # Reduce the exponent
            hk_exp = hk_exp // pi
        
        del bsgs.baby_steps
        dlogs.append(xi)
    return crt(dlogs, n_factors, n)

def dlog_backdoor(g,c,n,p,q):
    np = p-1
    np_factors = getFactors(np)
    
    nq = q-1
    nq_factors = getFactors(nq)
    

    xp = pohlig_hellman(g,c,p,np,np_factors)
    assert pow(g,xp,p) == pow(c,1,p)

    xq = pohlig_hellman(g,c,q,nq,nq_factors)
    assert pow(g,xq,q) == pow(c,1,q)

    x = crt([xp, xq], [(np, 1), (nq, 1)], np*nq)
    return x % order

n = 0x5bf9961e4bcfc88017e1a9a40958af5eae3b3ee3dcf25bce02e5d04858ba1754e13e86b78a098ea0025222336df6b692e14533dad7f478005b421d3287676843f9f49ffd7ebec1e8e43b96cde7cd28bd6fdf5747a4a075b5afa7da7a4e9a2ccb26342799965f3fb6e65e0bb9557c6f3a67568ccbfaaa7e3d6c5cb79dd2f9928111c3183bf58bd91412a0742bbfb3c5cebfb0b82825da0875c5ee3df208ce563f896d67287c8b9aad9943dd76e5eae1fc8abd473ec9f9e4f2b49b7897954ca77b8f00ed51949c7e4f1f09bd54b830058bd7f4da04e5228250ba062ec0e1d19fb48a05333aada60ecdfc8c62c15773ed7e077edba71621f6a6c10302cc9ed26ec9
c = 0x2475123653f5a4b842e7ac76829e896450126f7175520929a35b6a4302788ceff1a605ed30f4d01c19226e09fc95d005c61320d3bbd55cfebbc775332067ac6056c1969282091856eaa44ccaf5738ac6409e865bbd1186d69f718abd2b3a1dd3dc933a07ca687f0af9385406fd9ee4fa5f701ad46f0852bf4370264c21f775f1e15283444b3bf45af29b84bb429ed5a17adc9af78aee8c5351434491d5daf9dd3ce3cf0cd44b307eb403f0e9f482dd001b25ed284c4e6c1ba2864e5a2c4b1afe4161426cc67203f30553c88d7132aef1337eca00622b47cb7a28195f0e3a2ab934e6163b2941a4631412e13b1a72fe34e6480fada9af4dae14f2608805d61ee

p = pollard(n)
q = n // p


assert(p*q == n)
assert(gcd(p - 1, q - 1) == 2)

order = lcm(p - 1,q - 1) // 2

g = mpz(3)

FLAG = dlog_backdoor(g,c,n,p,q)

assert(c == pow(3, FLAG, n))

flag = long_to_bytes(FLAG).decode()
print(flag)