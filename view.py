# view.py
import sys
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"ENCFFv1\x00"

def derive_key(password: bytes, salt: bytes, iterations: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

def main():
    if len(sys.argv) not in (2, 3):
        print("Usage: python view.py <encrypted_file> [output_plainfile]")
        sys.exit(2)

    encfile = sys.argv[1]
    outpath = sys.argv[2] if len(sys.argv) == 3 else None

    with open(encfile, "rb") as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            print("File format not recognized.")
            sys.exit(1)
        salt = f.read(16)
        nonce = f.read(12)
        ciphertext = f.read()

    password = getpass.getpass("Enter password to decrypt: ").encode("utf-8")
    try:
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print("Decryption failed — wrong password or corrupted file.")
        sys.exit(1)

    if outpath:
        with open(outpath, "wb") as f:
            f.write(plaintext)
        print("Decrypted and saved to", outpath)
    else:
        # print to console (decoded as UTF-8 with replacement for safety)
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            text = plaintext.decode("utf-8", errors="replace")
        print("---- Decrypted content start ----")
        print(text)
        print("---- Decrypted content end ----")

if __name__ == "__main__":
    main()
