﻿import random
import hashlib
import binascii
import os

def hash_value(file_to_open):
    file = open(file_to_open, 'rb')
    content = file.read()
    file.close()
    hashed_sum_value = hashlib.sha256(content).hexdigest()
    return int(hashed_sum_value, 16)

def modular_exponent(a, power, mod):
    if power <= 0:
        return 1
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
    
def generate_p_and_q(bits_requested,save=True, file_name="p_q.txt"):
    p = generateRandomPrimeNumber(bits_requested)
    q = generateRandomPrimeNumber(bits_requested)
    #save p and q to file
    file = open(file_name, "w")
    file.write(str(p)+'\n'+str(q))
    file.close
    return (p, q)
    
def read_e_n(file_name="e_n.txt"):
    key_file = open(file_name, "r")
    contents = key_file.read()
    key_file.close()
    lines = contents.split('\n')
    return (int(lines[0]), int(lines[1]))
