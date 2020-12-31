* I just kind did `strings memorandum.bin | grep -i "flag"` and happened to stop it from printing at the correct time
* I saw the flag in:
```
flag\{e701f9290e2cd553be981461f8ea08e5\}\lang9\f1\par
flag
flagno
_FLAGS
GetTraceEnableFlags
flag\{e701f9290e2cd553be981461f8ea08e5\}\lang9\f1\par
%s - AsyncRecoSetFlags failed.
%s - AsyncRecoBackgroundSetFlags failed.
flag\{e701f9290e2cd553be981461f8ea08e5\}\lang9\f1\par
EtwGetTraceEnableFlags
Windows\CurrentVersion\Internet Settings\Cache!DebugFlag
```
* The flag is `flag{e701f9290e2cd553be981461f8ea08e5}`
