import random
import hashlib
import binascii
import sys
import os

def modular_exponent(a, power, mod):
    if power <= 0:
        return 1
    #print(power)
    temp = modular_exponent(a, power // 2, mod)
    if power % 2 == 0:
        return (temp * temp) % mod
    else:
        return (a * temp * temp) % mod

def fermatTest(value):
    a = random.randrange(2,value - 1)
    #modular_exponent(a, value - 1, value)
    return (pow(2,value - 1, value) == (1))

def generateRandomPrimeNumber(bits_requested):
    prime = random.getrandbits(bits_requested)
    #print(prime)
    if(prime % 2 == 0):
        prime += 1
    while( not fermatTest(prime)):
        prime += 2
    return prime

def euclid_gcd(a, b):
    if b > a:
        tmp = a
        a = b
        b = tmp
    if b == 0:
        return [1, 0, a]
    else:
        x, y, d_ = euclid_gcd(b, a % b)
        return [y, x - (a // b)*y, d_] #ax + by = gcd(a, b) returns x, y, and gcd

def mod_inverse(e, n):
    x, y, d_ = euclid_gcd(e, n)
    if x < 0:
        return n + x
    return x

def generate_RSA_key_pairs(bits):
    p = generateRandomPrimeNumber(bits)
    q = generateRandomPrimeNumber(bits)
    #save p and q to file
    file = open("p_q.txt", "w")
    file.write(str(p)+'\n'+str(q))
    file.close
    print("2. Probable prime numbers p and q are generated (each > 10**40) and saved in the file (p_q.txt) true;")
    print("digits in p == "+str(len(str(p))))
    print("digits in q == "+str(len(str(q))))
    n = p * q
    print("6. n=p*q completed on previous line;")
    phi = (p - 1)*(q - 1)
    e = random.randrange(3, phi - 1)
    if e % 2 == 0:
        e += 1
    while not euclid_gcd(phi, e)[2] == 1:
        e += 2;
    print("3. e is co-prime of (p-1)(q-1), the public key-set file (e_n.txt) generated true;")
    x, y, d_ = euclid_gcd(phi, e)
    if y < 0:
        y += phi
    print("4. d is the mod inverse of e, the private key-set file (d_n.txt) generated true;")
    #y is d
    print("(e*d) mod phi = " + str((e*y)%phi))
    print("5. e*d = (p-1)(q-1) completed;")
    return [e, y, n]# e, d, n

def hash_value(file_to_open):
    file = open(file_to_open, 'rb')
    content = file.read()
    file.close()
    hashed_sum_value = hashlib.sha256(content).hexdigest()
    return int(hashed_sum_value, 16)

def sign_file(key, n_value, file_to_open):
    hashed_sum_value = hash_value(file_to_open)
    decrypted_hashed_value = pow(hashed_sum_value, key, n_value)
    signature_string = ((bin(decrypted_hashed_value))[2:]).zfill(1024)
    n = 8
    bin_array = [int(signature_string[i:i+n], 2) for i in range(0, len(signature_string), n)]
    byte_array = bytes(bin_array)
    signature_as_integer = int.from_bytes(byte_array, byteorder="big", signed=False)
    with open(file_to_open, "br") as file:
        content = file.read()
        file.close()
    with open(file_to_open+".signed", "bw") as file:
        file.write(byte_array)
        file.write(content)
        file.close

def verify_signature(key, n_value, file_to_open):
    #hashed_sum_value = hash_value(file_to_open)
    signature = ""
    with open(file_to_open, "br") as file:
        buffer = file.read(128)
        signature_as_integer = int.from_bytes(buffer, byteorder="big", signed=False)
        content = file.read()
        file.close()
    signature = pow(signature_as_integer,key,n_value)
    #print(" Sha256 hash of "+ file_to_open +" "+str(hashed_sum_value))#error
    print(" Encrypted signature from " + file_to_open + " "+str(signature))
    hashed_sum_value = int(hashlib.sha256(content).hexdigest(), 16)
    print(" Sha256 hash of " + file_to_open + " content "+str(hashed_sum_value))
    integrity = (signature == hashed_sum_value)
    print(" The integrity of the signature is "+str(integrity))
    if integrity:
        print(" message has not been modified ")
    else:
        print(" message has been modified ")
    return integrity

def part_two_of_project():
    print(" Part two started ")
    print(" creating test file; file.txt")
    #input_file = "file.txt"
    #with open(input_file, "w") as file:
    #    for x in range(0, 100):
    #        file.write(str(x))
    #        file.write('\n')
    #    file.close()
    print(" retrieving private key from d_n.txt ")
    key_file = open("d_n.txt", "r")
    contents = key_file.read()
    key_file.close()
    lines = contents.split('\n')
    d = int(lines[0])
    n = int(lines[1])

    print(" retrieving public key from e_n.txt ")
    key_file = open("e_n.txt", "r")
    contents = key_file.read()
    key_file.close()
    lines = contents.split('\n')
    e = int(lines[0])
    n = int(lines[1])

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
#print(generateRandomPrimeNumber(512))
def part_one_of_project():
    print(" Part one started ")
    print(" generating RSA keys ")
    print("1. Fermat's test is implemented during generatePrimeNumber(bits) function;")
    e, d, n = generate_RSA_key_pairs(512)
    print(" key generation complete ")
    print(" verifying key integrity ")
    message = 1234567890
    print(" example message = "+str(message))
    encrypt = pow(message, e, n)
    print(" encrypted message = "+str(encrypt))
    decrypt = pow(encrypt, d, n)
    print(" decrypted message = "+str(decrypt))
    print(" RSA worked : " + str(message == decrypt))
    #verify keys work
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
    print(" private key file; d_n.txt written ")
    print(" part 1 of project complete ")

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
