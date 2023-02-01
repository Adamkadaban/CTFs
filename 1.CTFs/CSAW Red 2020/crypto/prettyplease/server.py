#!/usr/bin/python3
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
import os
import binascii

def int_of_string(s):
    return int(binascii.hexlify(s), 16)

def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    ctr = Counter.new(128, initial_value=int_of_string(iv))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return iv + aes.encrypt(plaintext)

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    ctr = Counter.new(128, initial_value=int_of_string(iv))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return aes.decrypt(ciphertext[16:])

def print_flag():
    try:
        with open("flag.txt") as f:
            message = f.read().strip()
        message = bytes(message, 'utf8')
        print(message)
    except IOError:
        return "Something went wrong when retrieving the flag on the server. Please contact an admin on Discord. Alternatively, you may be running this locally, in which case you need a flag.txt file in your local directory."

def reject_applicant():
    print("")
    print("   Thank you for applying for a flag from CSAW RED.")
    print("Our review committee spent a long time reflecting")
    print("on your competitive application, which was not")
    print("successful. Should you disagree with the result, feel")
    print("free to write another essay and reapply.")
    print("   Sincerely,")
    print("")
    print("The Committee for the Ethical Dissemination of Flags")
    return

def get_selection():
    print("Enter your selection:")
    print("1) Apply for a flag")
    print("2) Process application token")
    print("3) Exit")
    print("> ", end='')
    selection = input()
    if selection in list('123'):
        print("")
        return selection
    else:
        print("Error: Invalid selection.")
        exit(0)

def request_essay():
    print("------- A P P L I C A T I O N   P R O C E S S I N G   S Y S T E M -------\n")
    print("   To apply for a flag, in no more than five words, please give a detailed")
    print("explanation of what cryptography means to you and why you think we should")
    print("give you the flag.\n")
    print("-------------------------------------------------------------------------")
    print("> ", end='')
    essay = input() # TODO: See if anyone is available to actually read these essays.
    return essay

def request_token():
    print("------- C I P H E R T E X T   P R O C E S S I N G   S Y S T E M -------")
    print("")
    print("   Thank you for your interest in a CSAW RED cryptography flag. Please")
    print("enter the base64-encoded token that we gave you when you applied.\n")
    print("-------------------------------------------------------------------------")
    print("> ", end='')
    user_ct = input()
    return user_ct

def process_application(essay):
    return "Your application has been REJECTED" # TODO: recruit a review committee

def the_flag_gods_like_you(s):
    return(s == b'Your application has been ACCEPTED')

def main():
    print("*** Pretty Please ***\n")
    print("   Welcome to the official CSAW RED flag application.")
    print("Many people wish to receive flags, and we have hired a")
    print("special committee to review all flag requests. Decisions")
    print("will be made on a competitive basis and flags will be")
    print("issued to all those with demonstrated cryptographic")
    print("ability.\n")
    key = get_random_bytes(AES.block_size)
    while True:
        selection = get_selection()
        if (selection == "1"):
            essay = request_essay()
            application_result = process_application(essay).encode('utf-8')
            ct_bytes = encrypt_message(key, application_result)
            ct = b64encode(ct_bytes).decode('utf-8')

            print("   Here is an encrypted token containing the result of your application.")
            print("Submit this token to our proof of acceptance processing system and we")
            print("will inform you of the application results.\n")
            print("   Token: " + ct)
            print("")
        elif (selection == "2"):
            try:
                user_ct = b64decode(request_token())
                pt = decrypt_message(key, user_ct)
                if(the_flag_gods_like_you(pt)):
                    print("Congratulations! Here is your flag.")
                    print_flag()
                else:
                    reject_applicant()
            except:# ValueError, KeyError:
                print("Error during base64 decoding or decryption.")
            exit(0)
        elif (selection == "3"):
            print("Bye!\n")
            exit(0)

main()