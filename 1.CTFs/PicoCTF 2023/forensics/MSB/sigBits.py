import os
import binascii
import sys
from PIL import Image

def help(func=None):
    if func == None:
        print("Usage:\n\tsbPy [OPTIONS] [FILE]")
        print("\nOptions:\n\t-t=<lsb or msb>, --type=<lsb or msb>:\n\t\tChoose between read LSB or MSB (Default is LSB)\n\n\t-o=<Order sigle>, --order=<Order sigle>:\n\t\tRead the lsb or msb in the specify order (Default is RGB)\n\n\t-out=<Ouput name>, --output=<Output name>\n\t\tChoose the name of the output file (Default is outputSB)\n\n\t-e=<Row r Column>, --extract=<Row or Column>\n\t\tChoose between extracting by row or column (Default is Column)\n\n\t-b=<7 bits of your choice>, --bits=<7 bits of your choice>\n\t\tChoose the bits you want to extract info ( Have higher priority than '--type or -t' )")
    return

def extractBin(strInput, bits):
    strInput = strInput[2:]
    outputList = []

    while len(strInput) < 8:
        strInput = "0" + strInput

    for i in range(0,8):
        if bits[i] == '1':
            outputList.append(strInput[i])
    return outputList

def writeResults(outputFile, dataBin):
    resultFile = open(outputFile + ".txt", "w")
    size = len(dataBin)
    for i in range(0,size,8):
        # Each 8 bits convert into a int value
        value = int("".join(dataBin[i:i+8]),2)
        # Check if it is in the printable range
        if value >= 32 and value <= 126:
            resultFile.write(chr(value))
    resultFile.write("\n")
    resultFile.close()

def getSB(file, ord, outFile, ext, bits):
    dataBin = []
    with Image.open(file) as img:
        width, height = img.size
        xPattern = height
        yPattern = width
        if ext == "ROW":
            xPattern = width
            yPattern = height
        for x in range(0, xPattern):
            for y in range(0, yPattern):
                if ext == "ROW":
                    pixel = list(img.getpixel((x,y)))
                else:
                    pixel = list(img.getpixel((y,x)))

                R = extractBin(bin(pixel[0]), bits)
                G = extractBin(bin(pixel[1]), bits)
                B = extractBin(bin(pixel[2]), bits)
                if ord == "RGB":
                    dataBin.extend(R)
                    dataBin.extend(G)
                    dataBin.extend(B)
                elif ord == "RBG":
                    dataBin.extend(R)
                    dataBin.extend(B)
                    dataBin.extend(G)
                elif ord == "GRB":
                    dataBin.extend(G)
                    dataBin.extend(R)
                    dataBin.extend(B)
                elif ord == "GBR":
                    dataBin.extend(G)
                    dataBin.extend(B)
                    dataBin.extend(R)
                elif ord == "BRG":
                    dataBin.extend(B)
                    dataBin.extend(R)
                    dataBin.extend(G)
                else:
                    dataBin.extend(B)
                    dataBin.extend(G)
                    dataBin.extend(R)
    writeResults(outFile, dataBin)
    print("Done, check the output file!")

def checkParameters(file, parameters):
    order = 'RGB' # Default
    sbType = 'LSB' # Default
    outputFile = "outputSB" # Default
    extract = "COLUMN" # Default
    bitsSelection = None

    size = len(parameters)

    if file.find(".") == -1:
        print(f"INPUT ERROR: Unrecognized file type for '{file}'")
        exit()

    for i in range(size):
        # Help
        if parameters[i] == "--help" or parameters[i] == "-h":
            help()
            exit()
        # Order
        elif parameters[i][:3] == "-o=":
            order = parameters[i][3:].upper()
            if len(order) > 3:
                print(f"INPUT ERROR: Parameter '{order}' Exceeds parameter size ( Expected length = 3 )")
                exit()
            if order.find("R") == -1 or order.find("G") == -1 or order.find("B") == -1:
                print(order.find("R"), order.find("G"), order.find("B"))
                print(f"INPUT ERROR: Parameter '{order}' Has different characters than 'R,G,B' or repetitive character")
                exit()
        elif parameters[i][:8] == "--order=":
            order = parameters[i][3:].upper()
            if len(order) > 3:
                print(f"INPUT ERROR: Parameter '{order}' Exceeds parameter size ( Expected length = 3 )")
                exit()
            if order.find("R") == -1 or order.find("G") == -1 or order.find("B") == -1:
                print(f"INPUT ERROR: Parameter '{order}' Has different characters than 'R,G,B' or repetitive character")
                exit()
        # Type
        elif parameters[i][:3] == "-t=":
            sbType = parameters[i][3:].upper()
            if sbType != "LSB" and sbType != "MSB":
                print(f"INPUT ERROR: Type '{sbType}' Not recognized")
                exit()
        elif parameters[i][:7] == "--type=":
            sbType = parameters[i][7:].upper()
            if sbType != "LSB" and sbType != "MSB":
                print(f"INPUT ERROR: Type '{sbType}' Not recognized")
                exit()
        # Output file name
        elif parameters[i][:5] == "-out=":
            outputFile = parameters[i][5:]
        elif parameters[i][:9] == "--output=":
            outputFile = parameters[i][9:]
        # Bit selection
        elif parameters[i][:3] == "-b=":
            bitsSelection = parameters[i][3:]
            if len(bitsSelection) != 8:
                print(f"INPUT ERROR: Parameter 'bits' Expected 8 bits")
                exit()
            if int(bitsSelection, 2) == 0:
                print(f"INPUT ERROR: Parameter 'bits' Expected to have at least, one selected bit")
                exit()
        elif parameters[i][:7] == "--bits=":
            bitsSelection = parameters[i][7:]
            if len(bitsSelection) != 8:
                print(f"INPUT ERROR: Parameter 'bits' Expected 8 bits")
                exit()
            if int(bitsSelection, 2) == 0:
                print(f"INPUT ERROR: Parameter 'bits' Expected to have at least, one selected bit")
                exit()
        # Row or Column
        elif parameters[i][:3] == "-e=":
            extract = parameters[i][3:].upper()
        elif parameters[i][:10] == "--extract=":
            extract = parameters[i][10:].upper()
        else:
            print(f"INPUT ERROR: Parameter '{parameters[i]}' Not recognized")
            exit()
    # Set bitsSelection in the event that it has not been sent as a parameter 
    if not bitsSelection:
        if sbType == "LSB":
            bitsSelection = "00000001"
        elif sbType == "MSB":
            bitsSelection = "10000000"
    getSB(file, ord=order, outFile=outputFile, ext=extract, bits = bitsSelection)

def main(): # Adjustments for parameters
    if len(sys.argv) < 2:
        help()
        return
    elif len(sys.argv) == 2 and ( sys.argv[1] == '--help' or sys.argv[1] == '-h'):
        help()
        return
    checkParameters(sys.argv[-1:][0], sys.argv[1:-1])
main()
