#!/bin/bash
wget "https://365.csaw.io/files/8a30b2ec2193ddf25957bc71ec26c1a4/flash_c8429a430278283c0e571baebca3d139.zip" -O "flash.zip"
unzip flash.zip
strings flash_c8429a430278283c0e571baebca3d139.img | grep flag{.*}
