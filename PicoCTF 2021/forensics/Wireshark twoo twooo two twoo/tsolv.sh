#!/bin/bash
END=$(tshark -r shark2.pcapng -T fields -e tcp.stream | sort -n | tail -1)
for ((i=0;i<=END;i++))
do
    echo $i
    tshark -r shark2.pcapng -qz follow,tcp,ascii,$i > tcp-follow-stream-$i.txt
done
