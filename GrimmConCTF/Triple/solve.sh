#!/bin/bash
cat encoded.txt | cut -d " " -f 2 | base64 -d | base64 -d | base64 -d > flag.txt
