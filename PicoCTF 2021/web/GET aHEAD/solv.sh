#!/bin/sh

# We just have to make a HEAD request (as opposed to GET or POST) to the website

curl -I http://mercury.picoctf.net:47967/index.php? -s | egrep picoCTF{.*} -o > flag.txt
