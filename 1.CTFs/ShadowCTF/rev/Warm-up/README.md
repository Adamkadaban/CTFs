* We can disassemble the binary in ghidra
* The main looks like this:

```c
undefined8 main(void)

{
  puts("you need patience to get the flag.");
  sleep(0xe10);
  printf("{steppingstone}");
  return 0;
}

```
* The program sleeps for a long time and then prints the flag

* The flag is `shadowCTF{steppingstone}`
