# Encoding

## ASCII
* We just have to convert numbers to their ascii representations

```python3
nums = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
s = "".join([chr(i) for i in nums])
print(s)
```
* This gives us the flag: `crypto{ASCII_pr1nt4bl3}`

## Hex
* We can decode hex by typing the following in the terminal:
	* `echo "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d" | xxd -r -p`
	* This gives us the flag `crypto{You_will_be_working_with_hex_strings_a_lot}`

## Base64
* We can encode base64 by typing the following in the terminal:
	* `echo "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf" | xxd -r -p | base64`
	* This gives us the flag `crypto/Base+64+Encoding+is+Web+Safe/`

## Bytes and Big Integers
* The following code will turn the integer into text:

```python3
from Crypto.Util import number # do `apt install python3-pycryptodome` if you haven't yet

in = 11515195063862318899931685488813747395775516287289682636499965282714637259206269

d = number.long_to_bytes(in)

print(d.decode('UTF-8'))
```

* This gives us the flag `crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}`

## Encoding Challenge

