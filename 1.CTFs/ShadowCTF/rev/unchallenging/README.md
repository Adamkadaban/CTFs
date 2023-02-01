* We can disassemble the binary in ghidra

* The main function looks like this:
```c
undefined8 main(void)

{
  int iVar1;
  char local_108 [256];
  
  puts("What is the password?");
  gets(local_108);
  iVar1 = strcmp(local_108,"op3n_se5ame");
  if (iVar1 == 0) {
    puts("{Ar@b1an_night5}");
  }
  else {
    puts("Wrong!!");
  }
  return 0;
}
```
* Here, we can see that the password is `op3n_se5ame`, which outputs `{Ar@b1an_night5}`

* The flag is `shadowCTF{Ar@b1an_night5}`
