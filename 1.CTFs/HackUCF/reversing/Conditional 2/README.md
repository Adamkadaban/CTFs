* put the code into ghidra and look at the main:
```c
undefined8 main(int param_1,undefined8 *param_2)

{
  int iVar1;
  undefined8 uVar2;
  
  if (param_1 == 2) {
    iVar1 = atoi((char *)param_2[1]);
    if (iVar1 == -0x35010ff3) {
      puts("Access granted.");
      giveFlag();
      uVar2 = 0;
    }
    else {
      puts("Access denied.");
      uVar2 = 1;
    }
  }
  else {
    printf("Usage: %s password\n",*param_2);
    uVar2 = 1;
  }
  return uVar2;
}
```

* if `iVar1 == -0x35010ff3`, `giveFlag()` runs
* that's hex for -889262067

* running `./conditional2 -889262067` gets the flag: `flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}`
