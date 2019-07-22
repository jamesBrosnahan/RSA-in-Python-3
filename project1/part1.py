from rsa import *

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
