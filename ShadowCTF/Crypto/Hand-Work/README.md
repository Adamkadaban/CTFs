* This is clearly spoken morse code
* I uploaded the file to a [Speech-to-text engine](https://speech-to-text-demo.ng.bluemix.net/) and got all the words
* I then put it into a file and used python to convert to actual dots, spaces, and dashes: 

```python3
x = "dotdotdotspacedotdotdotdotspacedotdashspacedashdotdotspacedashdashdashspacedotdashdashspacedashdotdashdotspacedashdotdotdashdotspacedotspacedotdotdotdotdashspacedotdotdotspacedashdotdashdashspacedashdotdashdotspacedotdashdotspacedashdotdashdashspacedotdashdashdotspacedashspacedashdashdashdashdash"

newString = x.replace("dot",".").replace("space"," ").replace("dash","-")

print(newString)
```
* That gave me: `... .... .- -.. --- .-- -.-. -..-. . ....- ... -.-- -.-. .-. -.-- .--. - -----`

* We can then translate the morse code [here](https://morsecode.world/international/translator.html)
	* This got me `SHADOWC/E4SYCRYPT0`

* The flag is `ShadowCTF{e4sycrypt0}`

