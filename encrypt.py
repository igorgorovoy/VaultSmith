# encrypt.py
import os
import sys
import getpass
from cryptography.hazmat.primitives import hashes, kdf
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

"""
Usage:
  python encrypt.py export.csv encrypted.bin
"""

def derive_key(password: bytes, salt: bytes, iterations: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

def main():
    if len(sys.argv) != 3:
        print("Usage: python encrypt.py <input_plainfile> <output_encryptedfile>")
        sys.exit(2)

    infile = sys.argv[1]
    outfile = sys.argv[2]

    if not os.path.isfile(infile):
        print("Input file not found:", infile)
        sys.exit(1)

    password = getpass.getpass("Enter encryption password: ").encode("utf-8")
    password_confirm = getpass.getpass("Confirm password: ").encode("utf-8")
    if password != password_confirm:
        print("Passwords do not match.")
        sys.exit(1)

    # read plaintext
    with open(infile, "rb") as f:
        plaintext = f.read()

    # generate salt and derive key
    salt = os.urandom(16)  # store with file
    key = derive_key(password, salt)

    # AES-GCM encrypt
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # file format: [MAGIC(8)] [salt(16)] [nonce(12)] [ciphertext...]
    MAGIC = b"ENCFFv1\x00"  # custom magic to identify format/version
    with open(outfile, "wb") as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    print("Encrypted ->", outfile)
    print("Keep your password safe. Without it the file cannot be decrypted.")

if __name__ == "__main__":
    main()
