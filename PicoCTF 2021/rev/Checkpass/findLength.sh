#!/bin/sh
for i in {1..100}; do echo $i; ./checkpass `python3 -c "print('A'*$i)"`; done
