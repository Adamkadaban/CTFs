from Crypto.Util.number import bytes_to_long, getPrime

flag = "[REDACTED]"
p = getPrime(1024)
q = getPrime(1024)
e = 3
m = bytes_to_long(flag.encode("utf-8"))

n = p * q
c = pow(m, e, n)

print("e:" + str(e))
print("c:" + str(c))