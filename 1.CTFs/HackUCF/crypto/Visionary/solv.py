#!/bin/python3


with open('table.tsv') as fin:
    table = [i.rstrip().split() for i in fin.readlines()]

table[0].insert(0, "")

def lookup(s, key):
    sIndex = 0
    kIndex = 0
    for i in range(len(table)):
        if(table[0][i] == s):
            sIndex = i
            break
    for i in range(len(table)):
        if(table[i][0] == key):
            kIndex = i
            break
    return table[sIndex][kIndex]



def encode(s, key):
    r = ""
    for i in range(len(s)):
        r += lookup(s[i], key[i % len(key)])

    return r


with open('visionary/Cipher1.txt') as fin:
    c1 = fin.readline().rstrip()

with open('visionary/Decipher(Cipher1).txt') as fin:
    p1 = fin.readline().rstrip()

with open('visionary/cipherFlag.txt') as fin:
    c2 = fin.readline().rstrip()





alpha = "".join(table[1])[1:]

for a in alpha:
    for b in alpha:
        for c in alpha:
            for d in alpha:
                for e in alpha:
                    key = a + b + c + d + e
                    # print("Trying key",key)
                    if(encode(p1, key) == c1):
                        print(key)
                        break
