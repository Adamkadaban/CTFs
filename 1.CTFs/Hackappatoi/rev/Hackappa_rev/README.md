Run with `LD_PRELOAD='./libc6_2.34-0ubuntu1_amd64.so' ./hackappa_rev`

I found the libc [here](https://libc.blukat.me/?q=_rtld_global%3A0&l=libc6_2.34-0ubuntu1_amd64)

ghidra main shows that the `decrypt` function is called when:

```c
b == 10 && c == 7 && h == 11
```

Thus, we just need to press `1` 10 times, `2` 7 times, and `3` 11 times.



This outputs the flag: `HCTF{3z_Drunk_R3v}`
