#!/usr/bin/python3
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
iv = get_random_bytes(16)

def get_secret_message():
    try:
        with open("flag.txt") as f:
            message = f.read().strip()
        message = bytes(message, 'utf8')
        return message
    except IOError:
        return "Something went wrong when retrieving the flag on the server. Please contact an admin on Discord. Alternatively, you may be running this locally, in which case you need a flag.txt file in your local directory."

def pad(data):
    padlength = 16 - len(data)%16
    padding = chr(padlength)*padlength
    data += padding.encode('utf-8')
    return(data)

def get_selection():
    print("Enter your selection:")
    print("1) Ask about the flag")
    print("2) Ask about something else")
    print("3) End spell")
    print("> ", end='')
    selection = input()
    if selection in list('123'):
        print("")
        return selection
    else:
        print("Error: Invalid selection. Spell will terminate.")
        exit(0)

def get_message():
    print("Enter the base64-encoded thought you would like the admin to think about: ")
    try:
        print("> ", end='')
        thought = input()
        decoded_thought = b64decode(thought)
    except:
        print("Thought detection error. Your concentration may have been broken.")
        exit(0)
    return(decoded_thought)

def encrypt_message(data):
    padded = pad(data)
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ct_bytes = cipher.encrypt(pad(data))
    ct = b64encode(ct_bytes).decode('utf-8')
    return ct

def main():
    print("*** Mind Reader ***\n")
    print("   Your party wants to solve a crypto challenge, but")
    print("the challenge hasn't been released. So you ping an admin")
    print("via the Discord mailbot, and just ask for a crypto flag.")
    print("They don't give you the flag of course, but cleverly you")
    print("have cast a Detect Thoughts spell. Everything you say to")
    print("them, they can't help but think about -- and you can read")
    print("their mind when they do.\n")
    print("   You cannot believe it when their thoughts come back")
    print("encrypted. How can anyone think in code?? Oh, right, they")
    print("must be a programmer. Well, there must be some way to get")
    print("the flag...\n")

    while True:
        selection = get_selection()
        if (selection == "1"):
            message = get_secret_message()
        elif (selection == "2"):
            message = get_message()
        elif (selection == "3"):
            print("Bye!\n")
            exit(0)
        ct = encrypt_message(message)
        print("The admin is thinking: " + ct)
        print("")

main()