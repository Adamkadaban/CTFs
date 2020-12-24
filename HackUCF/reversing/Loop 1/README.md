* open the file in ghidra
* go to the main:
```c
undefined8 main(void)

{
  int iVar1;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined4 local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  
  while( true ) {
    while( true ) {
      puts("Menu:\n\n[1] Say hello\n[2] Add numbers\n[3] Quit");
      printf("\n[>] ");
      iVar1 = __isoc99_scanf(&DAT_0040203c,&local_c);
      if (iVar1 != 1) {
        puts("Unknown input!");
        return 1;
      }
      if (local_c != 1) break;
      printf("What is your name? ");
      local_78 = 0;
      local_70 = 0;
      local_68 = 0;
      local_60 = 0;
      local_58 = 0;
      local_50 = 0;
      local_48 = 0;
      local_40 = 0;
      local_38 = 0;
      local_30 = 0;
      local_28 = 0;
      local_20 = 0;
      local_18 = 0;
      iVar1 = __isoc99_scanf(&DAT_00402062,&local_78);
      if (iVar1 != 1) {
        puts("Unable to read name!");
        return 1;
      }
      printf("Hello, %s!\n",&local_78);
    }
    if (local_c != 2) {
      if (local_c == 3) {
        puts("Goodbye!");
      }
      else {
        if (local_c == 0x7a69) {
          puts("Wow such h4x0r!");
          giveFlag();
        }
        else {
          printf("Unknown choice: %d\n",(ulong)local_c);
        }
      }
      return 0;
    }
    printf("Enter first number: ");
    iVar1 = __isoc99_scanf(&DAT_0040209d,&local_10);
    if (iVar1 != 1) {
      puts("Unable to read number!");
      return 1;
    }
    printf("Enter second number: ");
    iVar1 = __isoc99_scanf(&DAT_0040209d,&local_14);
    if (iVar1 != 1) break;
    printf("%d + %d = %d\n",(ulong)local_10,(ulong)local_14,(ulong)(local_10 + local_14));
  }
  puts("Unable to read number!");
  return 1;
}

```
* the important bit is this:
```c
if (local_c == 0x7a69) {
          puts("Wow such h4x0r!");
          giveFlag();
        }
```
* if we input `0x7169`, which is the hex representation of `31337` in decimal, we run `giveFlag()`
* running `echo 31337 | ./loop1` gets the flag: `flag{much_reversing_very_ida_wow}`

