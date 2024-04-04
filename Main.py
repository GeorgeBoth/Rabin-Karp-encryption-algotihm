import random
from sympy import isprime

#docs:https://github.com/topics/rabin-karp-algorithm

"""The Rabin cryptosystem is an asymmetric encryption technique based on the computational difficulty of finding square roots modulo a composite number that is a product of two distinct prime numbers.
Key Generation:
Key Generation Process:
Select two large distinct prime numbers, denoted as p and q.
Compute the modulus n = p * q. This forms the public key.
The private key consists of the pair of primes (p, q).
Encryption:
Encryption Process:
Convert the plaintext message into numerical values, often representing characters or blocks of characters.
Encrypt by computing the ciphertext as the square of the plaintext modulo n: ciphertext = (plaintext^2) mod n.
Decryption:
Decryption Process:
Decrypt by calculating the square roots modulo n of the ciphertext. Due to the properties of quadratic residues, there could be up to four possible roots.
The original plaintext can be obtained by interpreting the roots or using additional information/context to discern the correct message.
"""
# Alphabet declaration
alphabet = ' ' + ''.join([chr(i) for i in range(33, 127)])

# Function to generate Rabin keys
def generate_keys():
    p = q = 4
    # Generating prime numbers p and q such that p and q are congruent to 3 mod 4
    while p % 4 != 3 or not isprime(p):
        p = random.getrandbits(8)
    while q % 4 != 3 or not isprime(q):
        q = random.getrandbits(8)
    n = p * q  # Calculate n, the product of p and q
    return n, p, q  # Return public key (n) and primes p, q

# Function to encrypt plaintext using Rabin algorithm
def encrypt(plaintext, public_key):
    if not all(char in alphabet for char in plaintext):
        raise ValueError("Invalid plaintext")
    encrypted_text = [pow(alphabet.index(char), 2, public_key) for char in plaintext]
    # Convert each character of the plaintext into its encrypted form using Rabin
    return encrypted_text

# Function to decrypt ciphertext using Rabin algorithm
def decrypt(ciphertext, private_key):
    if not all(isinstance(num, int) for num in ciphertext):
        raise ValueError("Invalid ciphertext")
    p, q = private_key[1], private_key[2]
    decrypted_text = []
    for num in ciphertext:
        # Use the Rabin decryption algorithm to recover the original characters
        root_p = pow(num, (p + 1) // 4, p)
        root_q = pow(num, (q + 1) // 4, q)
        # Applying the Chinese Remainder Theorem to find all possible roots
        # Recover the plaintext from the roots by applying the proper decoding mechanism
        # This step can result in multiple potential plaintexts due to Rabin's decryption ambiguity
        decrypted_text.append((root_p, root_q))
    return decrypted_text

# Step (iii): Encrypt plaintext with validation
public_key, p, q = generate_keys()
plaintext_to_encrypt = "asddadsd"
ciphertext = encrypt(plaintext_to_encrypt, public_key)
print(f"Plaintext: {plaintext_to_encrypt}")
print(f"Ciphertext: {ciphertext}")

# Step (iv): Decrypt ciphertext with validation
decrypted_text = decrypt(ciphertext, (public_key, p, q))
print(f"Decrypted text (multiple potential roots): {decrypted_text}")