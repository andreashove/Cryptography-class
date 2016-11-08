__author__ = 'Andreas Hove'

import random

BITS = ('0', '1')
ASCII_BITS = 8

'''######### MATHEMATICAL FUNCTIONS #########'''
def findPrime(n):
    '''
    Finds a number raised to power of n which is probably prime using the Fermat Method
    Discussed on page 2 in the report.
    '''
    p = 0
    while p == 0:
        ran = random.randint(2**(n-1), 2**n)
        if fermat(ran):
            p = ran
    return p

def fermat(n):
    '''
    Fermat Method used to verify if n is a probable prime.
    Discussed on page 2 and 3 in the report.
    '''
    for i in range(1, 5):
        a = random.randint(2, n-2)
        r = fast_exponentiation(a, n-1, n)
        if r != 1:
            return False
    return True

def crt(c, p, q, d):
    '''
    Chinese Remainder Theorem
    "Square and multiply"
    Discussed on page 2 in the report.
    '''
    dp = d % (p-1)
    dq = d % (q-1)
    qinv = modinv(q, p)
    m1 = fast_exponentiation(c, dp, p)
    m2 = fast_exponentiation(c, dq, q)
    h = qinv * (m1-m2) % p
    return m2 + h*q

def fast_exponentiation(a,b,n):
    '''
    Left-to-Right binary exponentiation
    Code from: http://aditya.vaidya.info/blog/2014/06/27/modular-exponentiation-python/
    Discussed on page 3 in the report.
    '''
    x = 1
    while(b>0):
        if(b&1==1):
            x = (x*a)%n
        a=(a*a)%n
        b >>= 1
    return x%n

def egcd(a, b):
    '''
    Extended Greatest Common Divider.
    Code from: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    This code is part of the modinv() function, which is discussed on page 2 in the report.
    '''
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

def modinv(a, m):
    '''
    Modular Inverse.
    Code from: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    Discussed on page 2 in the report.
    '''
    g, x, y = egcd(a, m)
    if g != 1:
        print("ERROR: Modular inverse does not exist. Following exception is now thrown.")
        raise Exception('modular inverse does not exist')
    else:
        return x % m

'''######### MAIN METHOD #########'''
def main():
    '''
    main method for this script.
    Discussed on page 1 in the report.
    '''
    print("###########")
    print("# # RSA # #")
    print("###########")
    print("\nPlease type a plaintext to encrypt (minimum 8 characters)")
    plaintext = input("Plaintext: ")
    print("\nEncrypt using private key? (default usage is the public key)")
    whichKeyAnswer = input("(y/n): ").lower()
    print("\nWhich key size would you like to use?")
    keysize = input("Key size: ")
    keysize = int(keysize)
    keysize //= 2

    e = 65537
    print("\nGenerating primes ..")
    p = findPrime(keysize)
    q = findPrime(keysize)

    n = p*q
    phi = (p-1)*(q-1)
    d = modinv(e, phi)
    encKey = e
    decKey = d

    print("\nEncryption parameters: \n"
         " - e: {}\n - p: {}\n - q: {}\n - d: {}".format(e, p, q, d))
    if whichKeyAnswer == "y":
        print(" - encrypting using private key .. ")
        encKey = d
        decKey = e
    else: print(" - encrypting using public key .. ")

    bits = string_to_bits(plaintext)
    blocks = []
    blocksize = 64
    for b in range((len(bits) // blocksize)):  # split blocks into block size
        block = bits[b*blocksize:(b+1)*blocksize]
        blocks.append(block)

    if (len(bits) % blocksize) != 0:
        length = len(bits)  # get length of block
        lastblock = bits[(b+1)*blocksize:length]  # create block of the actual size (less than block size)
        createlast = []
        emptyblock = [0]*(blocksize - len(lastblock))  # create block of leading zeroes

        for i in emptyblock:
            createlast.append(emptyblock[i])
        for bit in lastblock:
            createlast.append(bit)  # add the bits of the last block to the block with leading zeroes

        blocks.append(createlast)
    print("\nEncrypted integers: ", end="")
    for ch in blocks:
        string = bit_list_to_string(ch)
        integer = int(string,2)
        #enc = integer**encKey % n
        enc = fast_exponentiation(integer, encKey,n)
        print("{} ".format(enc), end="")
    print("\n\nTo decrypt, please input the enciphered integers")
    encipherbits = input("\nEnciphered integers: ")
    encipherbits = encipherbits.split(" ")

    if whichKeyAnswer == "y": print("\nDecrypting using public key .. ")
    else: print("\nDecrypting using private key .. ")

    decryptedBlocks = []
    for bl in encipherbits:
        dec = crt(int(bl),p,q,decKey)
        bits = convert_int_to_bits(dec)
        padded_bits = pad_bits(bits,len(bits) + (ASCII_BITS - (len(bits) % ASCII_BITS)))
        result = bits_to_string(padded_bits)
        decryptedBlocks.append(result)
    print("Decrypted message: ", end="")
    try: print(''.join(decryptedBlocks))
    except UnicodeEncodeError: print("Error: error during decryption.")

    return ''.join(decryptedBlocks)

'''######### HELPER FUNCTIONS #########'''
def string_to_bits(string):
    """
    Determines the format of input (string or int) and then the string is converted.
    Discussed on page 3 in the report.
    """
    result = []

    # text is ints
    try:
        if int(string):

            # text is int, but not binary
            if not all(x in "01" for x in string):

                result = convert_string_to_bits(string)
                return result

            # text is binary
            for b in string:
                result.append(int(b))
            return result

    # text is not binary
    except ValueError:
        pass

    # each character in 's' is converted to 8-bit block which is appended to the result
    result = convert_string_to_bits(string)

    return result

def convert_string_to_bits(string):
    """
    Converts each character in a string to bits, and returns a list of binary integers.
    Original code from: http://stackoverflow.com/questions/10237926/convert-string-to-list-of-bits-and-viceversa
    Modified to fit this implementation.
    Discussed on page 3 in the report.
    """
    result = []
    for c in string:
       bits = bin(ord(c))[2:]
       bits = '00000000'[len(bits):] + bits  # since all characters are 8 bit, bits is set to '00000000'
       result.extend([int(b) for b in bits])

    return result

def pad_bits(bits, pad):
    """
    pads seq with leading 0s up to length pad. Original code from: https://gist.github.com/barrysteyn/4184435
    Discussed on page 3 in the report.
    """
    assert len(bits) <= pad
    return [0] * (pad - len(bits)) + bits

def convert_int_to_bits(n):
    """
    converts an integer to bit array. Original code from: https://gist.github.com/barrysteyn/4184435
    Discussed on page 3 in the report.
    """
    result = []
    if n == 0:
        return [0]
    while n > 0:
        result = [(n % 2)] + result
        n = n // 2
    return result

def bits_to_string(b):
    """concatenates bits to a string of characters. Original code from: https://gist.github.com/barrysteyn/4184435"""
    return ''.join([bits_to_char(b[i:i + ASCII_BITS])
        for i in range(0, len(b), ASCII_BITS)])

def bits_to_char(b):
    """
    converts bits to characters. Original code from: https://gist.github.com/barrysteyn/4184435
    Discussed on page 3 in the report.
    """
    assert len(b) == ASCII_BITS
    value = 0
    for e in b:
        value = (value * 2) + e
    return chr(value)

def bit_list_to_string(b):
    """converts list of {0, 1}* to string. Original code from: https://gist.github.com/barrysteyn/4184435"""
    return ''.join([BITS[e] for e in b])

# Script runs the following code
answer = "y"
while answer == "y":
    main()
    answer = input("\nRerun program? (y/n)")
input("\nPress ENTER to exit")
