# RSA-in-Python-3Created using python version 3.5

run with python rsa435.py s <file to sign> or python rsa435.py v <file to verify>

program can be run without any commandline parameters, it will first prompt if you want to use the functions I used for testing
if the user user answers n it will ask for a file path for a file to sign or verify

fermat test is implemented in fermatTest function that takes one positive integer as a paramter

prime numbers are generated in generateRandomPrimeNumber function that takes the bits the prime should have as a positive integer

euclid_gcd provides extended euclid algorithm

generate_RSA_key_pairs takes a positive integer for the primes to use ~512 

