#!/bin/bash
strings kill.pcapng | grep -o flag{.*}
