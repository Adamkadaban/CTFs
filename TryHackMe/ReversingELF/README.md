# Crackme1
* Just running the file with `./crackme1` gets the flag:
`flag{not_that_kind_of_elf}`

# Crackme2
* Let's run strings on the file with `strings crackme2`:
* `super_secret_password` looks like it could be it
* Running `./crackme2 super_secret_password` confirms our suspicions and outputs the flag:
`flag{if_i_submit_this_flag_then_i_will_get_points}`

# Crackme3
* Let's run strings on the file with `strings crackme3`:
* There's a couple suspicious things here.
	* `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
	* `ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==`
* The second is a base64 string. Let's decode it with `echo "ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==" | base64 -d`
* It gives us what appears to be the flag without the flag{} part. Let's add it on:
`flag{f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5}` 

# Crackme4
* We don't know the password and it appears to have been obfuscated. Let's open it up in ghidra

### ghidra
* The relevent functions when decompiled with the `o` key are here:
```c
void get_pwd(long param_1)

{
  int local_c;
  
  local_c = -1;
  while (local_c = local_c + 1, *(char *)(param_1 + local_c) != '\0') {
    *(byte *)(local_c + param_1) = *(byte *)(param_1 + local_c) ^ 0x24;
  }
  return;
}



void compare_pwd(char *param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined8 local_28;
  undefined8 local_20;
  undefined2 local_18;
  undefined local_16;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = 0x7b175614497b5d49;
  local_20 = 0x547b175651474157;
  local_18 = 0x4053;
  local_16 = 0;
  get_pwd(&local_28);
  puts("THIS IS ME");
  puts(local_28);
  iVar1 = strcmp((char *)&local_28,param_1);
  if (iVar1 == 0) {
    puts("password OK");
  }
  else {
    printf("password \"%s\" not OK\n",param_1);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



undefined8 main(int param_1,undefined8 *param_2)

{
  if (param_1 == 2) {
    compare_pwd(param_2[1]);
  }
  else {
    printf("Usage : %s password\nThis time the string is hidden and we used strcmp\n",*param_2);
  }
  return 0;
}

}

```
* we can tell that there should only be one positional argument
* the argument is passed to a `compare_pwd` function
* from there, it looks like it is compared to the output of a `get_pwd` function
* luckily, this is running locally, so let's use gdb to get the password

### gdb
* open gdb with a positional argument: `gdb --args crackme4 fillerPassword`
* disassemble the appropriate function: `disassemble compare_pwd`
* we know we want to see the value of whatever is being compared, so let's set a breakpoint there: `break *0x00000000004006d2`
* run the code with `run`
* now we hit the breakpoint. let's see whats in the registers: `info registers`
* we see an address in rax: `0x7fffffffdfd0`
* we can view the string representation of what's inside that using `x/s 0x7fffffffdfd0`. We get the password

`my_m0r3_secur3_pwd`

# Crackme5
