* open the file in ghidra and look at the entry function
* double click on the function in the entry parameter
* that takes you to this code:
```c

undefined4 FUN_080484f4(int param_1,undefined4 *param_2)

{
  char *__s;
  size_t sVar1;
  char *__s_00;
  int iVar2;
  
  if (param_1 == 2) {
    __s = (char *)param_2[1];
    sVar1 = strlen(__s);
    __s_00 = (char *)malloc(sVar1 * 2);
    if (__s_00 == (char *)0x0) {
      fwrite("malloc failed\n",0xe,1,stderr);
    }
    else {
      sVar1 = strlen(__s);
      FUN_080486b0(__s,__s_00,sVar1,0);
      sVar1 = strlen(__s_00);
      if ((sVar1 == 0x40) &&
         (iVar2 = strcmp(__s_00,"ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ=="),
         iVar2 == 0)) {
        puts("Correct password!");
        return 0;
      }
      puts("Come on, even my aunt Mildred got this one!");
    }
  }
  else {
    fprintf(stderr,"Usage: %s PASSWORD\n",*param_2);
  }
  return 0xffffffff;
}
```
* the password is correct if something equals `ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==` (thats what strcmp(a,b)==0) means
* this looks like base64 so I can only assume the program is base64 encoding the password you input

* in bash i can write `echo "ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==" | base64 -d` which gets the output `f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5`

* if we run `./mildred f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5`, that's correct

* the password is the flag
