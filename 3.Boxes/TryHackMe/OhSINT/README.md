# OhSINT
* We can start by downloading the file and running `exiftool WindowsXP.jpg`
```
ExifTool Version Number         : 12.09
File Name                       : WindowsXP.jpg
Directory                       : .
File Size                       : 229 kB
File Modification Date/Time     : 2020:12:06 08:19:46-05:00
File Access Date/Time           : 2020:12:06 08:20:03-05:00
File Inode Change Date/Time     : 2020:12:06 08:20:00-05:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
XMP Toolkit                     : Image::ExifTool 11.27
GPS Latitude                    : 54 deg 17' 41.27" N
GPS Longitude                   : 2 deg 15' 1.33" W
Copyright                       : OWoodflint
Image Width                     : 1920
Image Height                    : 1080
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1920x1080
Megapixels                      : 2.1
GPS Latitude Ref                : North
GPS Longitude Ref               : West
GPS Position                    : 54 deg 17' 41.27" N, 2 deg 15' 1.33" W
```
* We can see a copyright to `OWoodflint`
* Looking that up on google with quotes surrounding it to get exact matched, we get :
	* [This](https://twitter.com/owoodflint?lang=en) twitter account
		* The image is of a cat
		* One of their tweets discloses a `BSSID: B4:5D:50:AA:86:41` 
	* [This](https://oliverwoodflint.wordpress.com/) wordpress blog
		* Their blogpost says they're currenly in New York
		* This was super random and took a while to find, but there's this white text here that can be found by either looking at the source code or just doing `CTRL-A`: `pennYDr0pper.!` (This is the password the room talks about)
	* [This](https://github.com/OWoodfl1nt?tab=repositories) github
		* One of their repos discloses their email: `OWoodflint@gmail.com`
		* It also says they're from London
* Exiftool also gave us a GPS Position, which when put into a [GPS translation site](https://www.gps-coordinates.net/), we get the address [195 5th Ave, New York, NY 11217](https://www.google.com/maps/place/40%C2%B044'30.8%22N+73%C2%B059'21.5%22W/@40.741899,-73.9914967,17z/data=!3m1!4b1!4m5!3m4!1s0x0:0x0!8m2!3d40.741895!4d-73.989308)
	* This matches up with their blogpost

* It took me a bit to remember this, but [WiGLE WiFI](https://wigle.net/) let's us look these up:
	* [This query](https://wigle.net/mapsearch?maplat=51.50830958528049&maplon=-0.13215182110323465&mapzoom=12#B4:5D:50:AA:86:41) gives us the following information:
```
UnileverWiFi
QoS: 7
type: infra
B4:5D:50:AA:86:41 ch:1
2017-10-10 - 2020-11-17
```
