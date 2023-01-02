# Programming

## Are you fast enough?

## Keep walking...

## A song...

## An arduino project

## Quizbot

# Forensics
## A message from space

## Lottery ticket
* Upload the image to [stegsolve](https://stegonline.georgeom.net/image)
	* Browse the bitplanes until you see the images have been changed
	* They are 42,88,25,48
	* Thus sum of those is `203`, which is the flag

## Lost evidence

# OSINT

## A quick search
* We can upload the image to [google](https://www.google.com/search?tbs=sbi:AMhZZis6AxTsyzCqOLFtS8O9mJEuGuiHX6lSD9XEApHQLfW7uYTnvrXKRsVvaDm_1ck3UXEm_12Ki_1Eot9YbgjKX5NZgkpxH9L6qCW6rT9HtW1ExXrp9VC8Eym3mVr31BKeK4_1QD3FNCAX3SBRERJMY-PvlqYQPuq24sJXgPTDHlU5WycH1X5U_1Nt4csgD56g7wC57OYLqsLmezdRfNd6wrAOVlWW4CvnPSpgqGWEk-kNqG8XwP8avFUP14UjiKtdiuA8km_1MAl9WDfiqyHf4Qca9EfCObO4AN7kKtQqLEi8fv4G_1NahKhn_1Mnnr3b0zNQXVeMLuJegIp2&btnG=Search%20by%20image&hl=en)
* This tells us the tower is called `Eben-Ezer Tower`

* The flag is `Eben-Ezer`

## Manhunt #1
* To find out who took the photo, we can look at the exif data with `exiftool icecream.jpg`
	* It was `Johnny Dorfmeister`

* The flag is `Johnny_Dorfmeister`

## Physical pentest setup

## Visit Limburg #1

## Bird call
* [This](https://birdnet.cornell.edu/api/) super cool website does some magic stuff to determine what bird it is
	* It's a White Stork

* In latin, that's [Ciconia ciconia](https://www.google.com/search?q=white+stork+in+latin&oq=white+stork+in+latin&aqs=chrome..69i57j0.3303j0j7&sourceid=chrome&ie=UTF-8)

* The flag is `Ciconia_ciconia`
## Visit Limburg #2

## Visit Limburg #3
# Reverse engineering / cracking

## Cookieee!

* Open `gameconqueror` (you can `apt install` it)
* Run the game and click a few times
	* Open GC an find the process
	* Then enter the number of cookies into the `value` field in GC
	* Do this a few times until you only have one address found on the left
	* Change the value to `10000000` and move back to the game. This gives the flag
* The flag is `brixelCTF{m3m0ry}`

## no peeking!

## registerme.exe

## android app
* I decompiled the app with `jadx brixelCTF.apk`
* Then I did `grep -r -o brixelCTF{.*}` to recursively search for a flag

* The flag is `brixelCTF{th3_4ndr0ids_y0u_4r3_l00k1ng_f0r}`
# Old tech

## punchcard
* [This](https://www.masswerk.at/card-readpunch/) website let me upload the image and gave me the flag

* The punchcard turns out to say `THE FLAG IS BRIXELCTF(M41NFR4M3) -- THANK YOU FOR PLAYING BRIXELCTF --`
* The flag is `BRIXELCTF(M41NFR4M3)`

## Goodbye old friend
* I found a flash disassembler on apt called flasm
* I ran `flasm -d goodbye.swf`, which showed me the movie:
```
movie 'goodbye.swf' compressed // flash 8, total frames: 115, frame rate: 12 fps, 400x300 px

  defineMovieClip 3 // total frames: 1
  end // of defineMovieClip 3
  
  initMovieClip 3
    constants 'Goodbye flash old friend, you gave me loads of entertainment. The flag is brixelCTF{n0_m0r3_5upp0rt}'  
    push 'Goodbye flash old friend, you gave me loads of entertainment. The flag is brixelCTF{n0_m0r3_5upp0rt}'
    trace
  end // of initMovieClip 3

  defineMovieClip 6 // total frames: 26
  end // of defineMovieClip 6
end
```
* The flag is `brixelCTF{n0_m0r3_5upp0rt}`

## The tape - WIP



# Cryptography
## Sea code
* [This](https://morsecode.world/international/decoder/audio-decoder-adaptive.html) website decodes morse code
	* The audio turns out to be `5E E+ FOR THIS CHALLENGE IS SEAGULL`
	* The flag is `seagull`

## Merde
* "A **french** messenger" tipped me off that this is the vigenere cipher
* We can use [dcode](https://www.dcode.fr/vigenere-cipher) to decode it
	* The ciphertext is `Vvr ktdk vl jvtzsyHBI{fnzcievs}` and the key is `confidentiel`
	* It becomes `The flag is brixelCTF{baguette}`

* The flag is `brixelCTF{baguette}`

## Merda
* "An **Italian** messenger" tipped me off that this is a shift cipher
* We can use [dcode](https://www.dcode.fr/caesar-cipher) to decode it
	* The ciphertext is `ymj kqfl nx gwncjqHYK{uneefsfutqn}` and the shift is `V`, which is the roman numeral for `5`
	* It becomes `the flag is brixelCTF{pizzanapoli}`

* The flag is `brixelCTF{pizzanapoli}`

## s̸͖̾̀͊͠h̸̜̒ï̷̧̲͙̭̤͛͒̋t̷̢̲͚͖̑͜
* "**64** parsecs from his **base** and the "=" at the end of the message tipped me off that this is base64

* Here's my code:
```python3
import base64

initString = "MDExMTAxMDAgMDExMDEwMDAgMDExMDAxMDEgMDAxMDAwMDAgMDExMDAxMTAgMDExMDExMDAgMDExMDAwMDEgMDExMDAxMTEgMDAxMDAwMDAgMDExMDEwMDEgMDExMTAwMTEgMDAxMDAwMDAgMDExMDAwMTAgMDExMTAwMTAgMDExMDEwMDEgMDExMTEwMDAgMDExMDAxMDEgMDExMDExMDAgMDEwMDAwMTEgMDEwMTAxMDAgMDEwMDAxMTAgMDExMTEwMTEgMDExMTAwMTAgMDExMDExMTEgMDExMDAwMTAgMDExMDExMTEgMDExMDAwMTEgMDExMDExMTEgMDExMTAwMDAgMDExMTExMDE="

unbased = base64.b64decode(initString) # this gives us a bunch of binary strings

nums = [int(i,2) for i in unbased.split()] # We can convert from int to digit

chrs = [chr(i) for i in nums] # We can convert those digits to ascii characters

flag = "".join(chrs) # join the characters

print(flag)

```

* Here's the oneliner ;) `python -c 'import base64; print("".join([chr(int(i,2)) for i in base64.b64decode("MDExMTAxMDAgMDExMDEwMDAgMDExMDAxMDEgMDAxMDAwMDAgMDExMDAxMTAgMDExMDExMDAgMDExMDAwMDEgMDExMDAxMTEgMDAxMDAwMDAgMDExMDEwMDEgMDExMTAwMTEgMDAxMDAwMDAgMDExMDAwMTAgMDExMTAwMTAgMDExMDEwMDEgMDExMTEwMDAgMDExMDAxMDEgMDExMDExMDAgMDEwMDAwMTEgMDEwMTAxMDAgMDEwMDAxMTAgMDExMTEwMTEgMDExMTAwMTAgMDExMDExMTEgMDExMDAwMTAgMDExMDExMTEgMDExMDAwMTEgMDExMDExMTEgMDExMTAwMDAgMDExMTExMDE=").split()]))'`

* The flag is `brixelCTF{robocop}`

## Scheiße
* "A **german** messenger" and all of the settings tipped me off that this is the Enigma machine
* We can use [cryptii](https://cryptii.com/pipes/enigma-machine) to decode it
* Plug in all the settings and the text and the output is `derfl agist sauer kraut`, which translates to `the flag is sour kraut`

* The flag is `sauerkraut`

## flawed
* The hash looks like md5, which is easy to crack
	* Thus, we can just look it up and google and see that [tons of people](https://md5.gromweb.com/?md5=d269ce15f9c44bc3992a5f4e5f273e06) have already cracked it

* The md5 hash `d269ce15f9c44bc3992a5f4e5f273e06` has a reverse of `notsecure`

* The flag is `notsecure`

## Don't be salty
* Because we know that the password is short and only has 26^5 possibilities, we can try to bruteforce it
	* `hashcat -m 10 -a 3 '2bafea54caf6f8d718be0f234793a9be:04532@#!!' ?l?l?l?l?l`
		* `-m 10` is the mode for md5 hash:salt
		* `-a 3` is the attack mode for bruteforce
		* `?l?l?l?l?l` indicates 5 lowercase letters

* The password and flag is `brute`

# Internet
## Easy
* We can get the flag in the html source `curl -s https://ctf.brixel.space/ | grep -o brixelCTF{.*}`
	* The flag is `brixelCTF{notsosecret}`

## Hidden Code
* I looked up the [konami code](https://cdn.vox-cdn.com/thumbor/aoQFyyKR4mHMRYArszFQr1r5VcY=/0x0:1024x768/920x613/filters:focal(431x303:593x465):format(webp)/cdn.vox-cdn.com/uploads/chorus_image/image/66380852/ERtzjdMUwAEsRXl.0.png) and it was a video game cheat code
	* If we type in up, up, down, down, left, right, left, right, b, a - mario runs past
* The flag is `mario`

## robotopia
* We can get the flag on robots.txt with `curl -s http://timesink.be/robotopia/robots.txt | grep -o brixelCTF{.*}`
	* The flag is `brixelCTF{sadr0b0tz}`

## Discord
* Looking at the rules page in the discord gives the flag `brixelCTF{th4nk5_f0r_r34d1ng_th3_rulz}`

## login1
* The password is hardcoded in the website
* We can get the flag in the source with `curl -s http://timesink.be/login1/index.html | grep -o brixelCTF{.*}`
	* The flag is `brixelCTF{w0rst_j4v4scr1pt_3v3r!}`

## Browsercheck
* I looked up "ask jeeves crawler" and found out it's a [user agent]
* We can change the user-agent with curl: `curl -s -H "User-Agent":"Mozilla/5.0 (compatible; Ask Jeeves/Teoma; +http://about.ask.com/en/docs/about/webmasters.shtml)" http://timesink.be/browsercheck/ | grep -o brixelCTF{.*}`
	* The flag is `brixelCTF{askwho?}`

## Readme
* The guide on the website says the flag is `freepoints`

## SnackShack awards
* I used inspect element to edit the dropdown value of the shack to 5000 and clicked vote
	* The flag is `brixelCTF{bakpau}`

## Flat earth
* Inspect element on the page shows a page `/admin.php`
	* From here, we can do an sql injection with `' OR 1=1 #;` in both fields
	* This gives us the flag `brixelCTF{aroundtheglobe}`

## Hiding in the Background
* Looking at the html source of the homepage shows a [background image](https://ctf.brixel.space/files/7150e745dc874ec7ae7a8d8fc8fa0aba/ctfbg.svg)
	* Downloading that and running `strings ctfbg.svg | grep -o brixelCTF{.*}` gives the flag: `brixelCTF{happy_holidays}`

## Dadjokes - WIP
* The comment at the bottom of the html source tells us that the original index is at `/index_backup.html`

* From here, we can see that the page has a bunch of php files
* We are also allowed to submit our own files with custom content and filenames
* Didn't end up getting it, but I have a feeling we could upload a php reverse shell

## Pathfinders #1
* Looking at the source, we see a few possible attack vectors:
	* `index.php?page=locations.php` might allow for local file inclusion
	* `admin/index.php` is the admin page
		* We can't log in to this, so let's try the first one

* We can run through multiple files with `wfuzz -z file,/usr/share/wordlists/dirb/common.txt http://timesink.be/pathfinder/index.php?page=admin/FUZZ` 
	* `.htaccess` and `.htpasswd` have different response lengths to the rest

* Going to `http://timesink.be/pathfinder/index.php?page=admin/.htpasswd` gives us the flag: `brixelCTF{unsafe_include}`
# Steganography
## Doc-ception
* Extract files with `foremost loremipsum.docx`
* `cd output` and `grep -r --text flag`
	* We can see `flag.txt` and `flag=openxml`
* The flag is `openxml`

## Limewire audio
* Put the audio into a [spectogram](https://academo.org/demos/spectrum-analyzer/)
	* The character is hello kitty
	* The flag is `hellokitty`

## Scan me
* I scanned the qr code with an app on my phone and got taken to this website: `http://www.timesink.be/qrcode/flag.html`

* Then I had to scan a bar code 3 times with the same app.
	* The codes were `code-128-easy`, `5449000133335`, and `congratulations_this_is_the_last_barcode`
* The flag is then shown as `brixelCTF{m4st3r_0f_sc4n5}`

## Rufus the vampire cat
* We can run steghide without a password on the image
* `echo "" | steghide extract -sf rufus.jpg`
	* This puts the following in a file: `You thought this was a cute cat picture? NOPE! Chuck Testa! (the flag is: chucktesta)`
	* The flag is `chucktesta`
