#!/bin/python3

from PIL import Image

lemur = Image.open("lemur.png")
flag = Image.open("flag.png")

lemurPixels = lemur.load()
flagPixels = flag.load()

XORdImage = Image.new(mode = "RGB", size = lemur.size)

for i in range(lemur.size[0]):
	for j in range(lemur.size[1]):
		l = lemurPixels[i,j]
		f = flagPixels[i,j]

		r = l[0] ^ f[0]
		g = l[1] ^ f[1]
		b = l[2] ^ f[2]

		XORdImage.putpixel((i,j), (r,g,b))

XORdImage.save("XORdImage.png")
