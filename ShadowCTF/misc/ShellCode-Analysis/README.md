* Looking at the last line of shellcode, we have:
```c
  return (v10)(0, &v12, &v12, 0, v10 ^ 536861646F77, v10 ^ 0x4354467B,v10 ^ 0x7368654C4C, v10 ^ 0x2D416E616C79, v10 ^ 0x7369732D, v10 ^ 646F6E337D);
```

* We can simply convert the hex values to text to get what is returned:

```python3
from Crypto.Util.number import *

hexVals = [0x536861646F77, 0x4354467B,0x7368654C4C, 0x2D416E616C79,0x7369732D, 0x646F6E337D]

s = b"".join([long_to_bytes(i) for i in hexVals]))

print(s.decode('UTF-8')
```

* The flag is `ShadowCTF{sheLL-Analysis-don3}`
