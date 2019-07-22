from rsa import *

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
