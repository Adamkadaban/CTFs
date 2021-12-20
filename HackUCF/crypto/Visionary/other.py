cipherText = "visionary/Cipher1.txt"
plainText = "visionary/Decipher(Cipher1).txt"
flagCipherText = "visionary/cipherFlag.txt"
tableFile = "table.tsv"

with open(cipherText) as fin:
    cipher = fin.readline().rstrip()

with open(plainText) as fin:
    plain = fin.readline().rstrip()

with open(flagCipherText) as fin:
    flag = fin.readline().rstrip()


with open(tableFile) as fin:
    table = [i.rstrip().split() for i in fin.readlines()]

table[0].insert(0, "") # might have to modify this part.
			# just a 2d array with the lookup table
			# should still work if the table is slightly off, but the key will be wrong
key = ""
for i, c in enumerate(plain[0:100]):
  col = table[0].index(c)
  for row in range(len(table)):
    if table[row][col] == cipher[i]:
      key += table[row][0]
      break

print(key)

dec_flag = ""
for i, c in enumerate(flag[:-1]):
  col = table[0].index(key[i])
  for row in range(len(table)):
    if table[row][col] == flag[i]:
      dec_flag += table[row][0]
      break

print(dec_flag)
