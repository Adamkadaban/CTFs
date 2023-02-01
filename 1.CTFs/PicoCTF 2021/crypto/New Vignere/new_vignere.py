import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16] # abcdefghijklmnop


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

correctOut = "ep df gl kf nb jb hb pi co hi dj gk hf ne je ec mj fn ej dd gm hp nd mc hb mi fn ep dh dm hb ah".split()

# flag = "redacted" # hex string, 32 characters

# key = "redacted" # all characters in abcdefghijklmnop and length < 15

def enc(flag,key): 
	b16 = b16_encode(flag)
	enc = ""
	for i, c in enumerate(b16):
		enc += shift(c, key[i % len(key)])
	return enc

