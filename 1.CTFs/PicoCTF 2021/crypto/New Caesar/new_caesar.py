import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def b16_encode(plain):
	enc = ""
	for c in plain:
		binary = "{0:08b}".format(ord(c))
		enc += ALPHABET[int(binary[:4], 2)]
		enc += ALPHABET[int(binary[4:], 2)]
	return enc

def shift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 + t2) % len(ALPHABET)]



def enc(flag, key):
	b16 = b16_encode(flag)
	enc = ""
	for i, c in enumerate(b16):
		enc += shift(c, key[i % len(key)])
	return enc

possibleKeys = 'abcdefghijklmnop'

passwd = "kj li jd li lj hd jd hf kf kh hj kk hh ki hl hn hg he kf hm hj hk hf he kf kk kj kg hg hj hl hg hm hh hf ki kf kf hm".split()

key = "e" # brute forced by finding out which keys were possible and overlapping. e was the only one that worked for all above outputs

s = ""

for ch in passwd:
	for i in range(ord('!'), ord('~') + 1):
		if enc(chr(i),key) == ch:
			s += chr(i)
			break

print(f'picoCTF{{{s}}}')

