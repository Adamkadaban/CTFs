#!/bin/bash
wget "https://365.csaw.io/files/331862688312d10999dd225275b46f64/df2014.zip"
unzip df2014.zip
cat * | strings | grep -o flag{.*} | sed -n 1p
