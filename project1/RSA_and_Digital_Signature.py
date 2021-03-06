﻿import random
import hashlib
import binascii
import sys
import os

from rsa import *
from part1 import *
from part2 import *

def part_two_of_project():
    print(" Part two started ")
    print(" creating test file; file.txt")
    print(" retrieving private key from d_n.txt ")
    key_file = open("d_n.txt", "r")
    contents = key_file.read()
    key_file.close()
    lines = contents.split('\n')
    d = int(lines[0])
    n = int(lines[1])


    print(" retrieving public key from e_n.txt ")
    e, n = read_e_n()

    print(" Signing file using sha256 algorithm ")
    print(" Signing and verifying files provided in rubric ...")
    count = 0
    files = ["bible_part1.txt", "monkey.jpg", "bible_part1.docx", ]
    for file in files:
        input_file = file
        if count == 0:
            print("Starting with " + input_file)
            count += 1
        else:
            print(" Verifying " + input_file)
        sign_file(d, n, input_file)
        print(" Verifying file signature and integrity ")
        integrity = verify_signature(e, n, input_file+".signed")
        if integrity:
            print(" Signature and message verified ")
        else:
            print(" Signature and message verification failed ")
    print(" part two complete, exiting program ... ")
    


if len(sys.argv) > 1:
    if os.path.isfile("d_n.txt") and os.path.isfile("e_n.txt"):
        pass
    else:
        e, d, n = generate_RSA_key_pairs(512)
        print(" writing files e_n.txt and d_n.txt ")
        with open("e_n.txt", "w") as public_key_file:
            public_key_file.write(str(e))
            public_key_file.write('\n')
            public_key_file.write(str(n))
            public_key_file.close()
        print(" public key file; e_n.txt written ")
        with open("d_n.txt", "w") as private_key_file:
            private_key_file.write(str(d))
            private_key_file.write('\n')
            private_key_file.write(str(n))
            private_key_file.close()

    if str(sys.argv[1]) == 's':
        input_file = str(sys.argv[2])
        key_file = open("d_n.txt", "r")
        contents = key_file.read()
        key_file.close()
        lines = contents.split('\n')
        d = int(lines[0])
        n = int(lines[1])
        sign_file(d, n, input_file)
        print(sys.argv[2] + " signed; run python ./Project1_RSA_and_Digital_Signature.py v "+sys.argv[2] + ".signed ")
    elif str(sys.argv[1]) == 'v':
        input_file = str(sys.argv[2])
        key_file = open("e_n.txt", "r")
        contents = key_file.read()
        key_file.close()
        lines = contents.split('\n')
        e = int(lines[0])
        n = int(lines[1])
        integrity = verify_signature(e, n, input_file)
        if integrity:
                print(" Signature and message verified ")
        else:
                print(" Signature and message verification failed ")
    else:
        response = input(" Do you want to run part one test function?note:(you must answer with y if it is the first running the program) y/n \n")
        if response == 'y':
            part_one_of_project()
        response = input(" Do you want to sign and verify the test files from the rubric? y/n \n")
        if response == 'y':
            part_two_of_project()
        else:
            response = input(" Do you want to sign a file? y/n \n")
            if response == 'y':
                response = input(" Supply path to a file to sign \n")
                input_file = response
                key_file = open("d_n.txt", "r")
                contents = key_file.read()
                key_file.close()
                lines = contents.split('\n')
                d = int(lines[0])
                n = int(lines[1])
                sign_file(d, n, input_file)
                response = input(" Do you want to verify the file signed? y/n \n")
                if response == 'y':
                    key_file = open("e_n.txt", "r")
                    contents = key_file.read()
                    key_file.close()
                    lines = contents.split('\n')
                    e = int(lines[0])
                    n = int(lines[1])
                    integrity = verify_signature(e, n, input_file+".signed")
                    if integrity:
                        print(" Signature and message verified ")
                    else:
                        print(" Signature and message verification failed ")
response = input(" press enter to close program ")
