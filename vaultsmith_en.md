
#  VaultSmith - a secure bridge between Firefox and KeePass

_How to protect your passwords after exporting them from your browser and turn them into a safely encrypted vault._

---

###  The Problem

Browsers store passwords conveniently, but not always securely.  
Firefox allows you to **export logins to CSV**, but here’s the catch: this file is **plain text**, where all your passwords are visible.  

For anyone who cares about data security, that’s not acceptable.

---

###  The Solution: VaultSmith

**VaultSmith** is a lightweight CLI tool designed for **secure password encryption** after exporting them from Firefox and **importing them into KeePass**.  
It doesn’t break browser security - it strengthens it.

---

###  Core Features

-  **AES-GCM Encryption** - strong, authenticated encryption standard protecting your data from unauthorized access.  
-  **KDF PBKDF2 / Argon2** - slows down brute-force attacks.  
-  **KeePass Import** - converts Firefox-exported CSV into a `.kdbx` database.  
-  **Domain Grouping** - automatically organizes entries by site.  
-  **Optional Keyfile** - adds a second layer of protection to your vault.  

---

###  VaultSmith Architecture

VaultSmith consists of three small Python utilities:

| Module | Purpose |
|--------|----------|
| `encrypt.py` | Encrypts CSV or any file into a secure binary `.enc` format |
| `view.py` | Decrypts and displays content (after password entry) |
| `csv_to_kdbx.py` | Converts CSV into a KeePass `.kdbx` database |

---

###  How It Works

1. **Export Logins from Firefox**  
   - Open `about:logins` → ⋯ → **Export Logins…**  
   - Save the file as `export.csv`  

2. **Encrypt the CSV**  
   ```bash
   python encrypt.py export.csv export.enc
   ```
   The `export.enc` file is now your secure, encrypted container.

3. **Decrypt When Needed**  
   ```bash
   python view.py export.enc
   ```

4. **Create a KeePass Database**  
   ```bash
   python csv_to_kdbx.py export.csv my_passwords.kdbx --group-by-domain
   ```

   VaultSmith automatically:  
   - creates the `.kdbx` file,  
   - prompts for a password,  
   - and organizes entries by domain.

---

###  Installation

Create a `requirements.txt` file:

```text
pykeepass>=4.0.0
python-dateutil>=2.8.2
cryptography>=40.0.0
argon2-cffi>=23.1.0  # optional
```

Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

###  Encryption Under the Hood

VaultSmith doesn’t reinvent cryptography - it uses proven, open standards:

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

salt = os.urandom(16)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
key = kdf.derive(password_bytes)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
```

>  File format: `[MAGIC][salt(16)][nonce(12)][ciphertext...]`

---

##  Verified Crypto Algorithms - Why You Can Trust Them

Below is a concise summary of the cryptographic algorithms used by VaultSmith and who has actually verified their security.

### AES-GCM (AES-256 in GCM mode)

- **Status:** NIST standard (FIPS 197 for AES, SP 800-38D for GCM).  
- **Proven by time:** decades of open cryptanalysis, used in TLS, SSH, IPsec, and hardware acceleration (AES-NI).  
- **Properties:** AEAD - provides **confidentiality and integrity**.  
- **Best practices:** unique 96-bit nonce for every encryption; rotate keys after large volumes of data.

### PBKDF2 (HMAC-SHA256)

- **Status:** RFC 2898, recommended in NIST SP 800-132.  
- **Reliability:** widely adopted, safe with sufficient iterations (≥100k–200k).  
- **Limitation:** CPU-bound - vulnerable to GPU/ASIC brute-force. Prefer **Argon2id** for modern security.

### Argon2 (Recommended: Argon2id)

- **Status:** Winner of the 2015 Password Hashing Competition (PHC), peer-reviewed by cryptographers worldwide.  
- **Strengths:** **memory-hard** design - significantly slows down GPU/ASIC attacks; tunable parameters for memory, time, and parallelism.  
- **Recommended parameters:** memory 64–256 MiB, time cost 2–4, parallelism 1–4, salt 16 bytes.

> ✅ **In short:** AES-GCM + Argon2id is a modern and robust combination for encrypting data derived from human passwords. PBKDF2 remains acceptable for maximum compatibility.

---

### ⚠️ Threats and How to Avoid Them

- **Nonce reuse in GCM** - catastrophic; always use random 12-byte nonces.  
- **Weak passwords** - even the best KDF can’t save a short passphrase. Use **16–20+ character passphrases**.  
- **KDF parameters** - tune them for ~0.3–1 s derivation time on your machine.  
- **Keep libraries updated** - regularly update `cryptography`, `argon2-cffi`, OpenSSL, and libsodium.

---

###  Why KeePass

KeePass is a **decentralized password manager**.  
It doesn’t rely on cloud storage, supports open formats, and gives you complete control over your vaults.  
VaultSmith simply automates the migration: CSV → `.kdbx`.

---

### ⚠️ Security Recommendations

- Immediately **delete the CSV** after creating `.enc` or `.kdbx`.  
- Use **16+ character passphrases**.  
- Store `.kdbx` in **encrypted storage** (e.g., S3 with KMS).  
- For additional protection - **use a keyfile**.  
- Never share your master password.

---

###  Roadmap

- ✅ Native **Argon2** KDF support  
- ✅ KeePassXC CLI integration  
- 🔄 Automatic secure-delete after import  
- 🧭 GUI version (Tauri / Electron)  
- ☁️ Optional S3 backup with KMS encryption  

---

###  License & Ethics

VaultSmith is designed **for your own credentials**.  
Using it to access someone else’s data is **illegal**.  
The author assumes no liability for misuse.

---

###  Conclusion

VaultSmith is a simple yet powerful way to **transform an unprotected password CSV into a secure KeePass database**.  
It combines verified cryptographic algorithms (AES-GCM + Argon2/PBKDF2), clean code, and full offline autonomy - no cloud services, no tracking, no compromise.

> 🏗️ **Forge your own vaults.**  
> VaultSmith - your forge of digital security.
