> Your party's cleric was scrying on the admins and intercepted one of them casting a "Contact Other Plane" spell. See if you can make sense of this traffic, then report who they contacted here: nc [web.red.csaw.io](http://web.red.csaw.io/) 5019

1. Use tshark to extract the data

    ```bash
    tshark -r otherplane.data -Y "icmp && ip.dst == 10.15.200.47 && frame.number >= 4" -T fields -e data | xxd -r -p > data.bin

    ```

2. Use binwalk to carve files from the data

    ```bash
    binwalk -D ".*" data.bin -C files
    ```

3. Open the images in the file directory
    - The image says `galactic octopus`
4. Type this into the netcat

    ```bash
    echo "galactic octopus" | nc web.red.csaw.io 5019
    ```

5. The flag is flag{m0r3_l1k3_c0n74c7_9l455_pl4n3}
