from helpers import *

def generate_RSA_key_pairs(bits, p_and_q_file_name = "p_q.txt", ):
    
    p, q = generate_p_and_q(bits)
    print("2. Probable prime numbers p and q are generated (each > 10**40) and saved in the file ("+p_and_q_file_name+")")
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
