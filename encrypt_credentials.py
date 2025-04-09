from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import os

def generate_key():
    """Generate or load AES-256 key."""
    if not os.path.exists("aes_key.bin"):
        key = AESGCM.generate_key(bit_length=256)
        with open("aes_key.bin", "wb") as f:
            f.write(key)
        print("🔐 AES key created.")
    else:
        with open("aes_key.bin", "rb") as f:
            key = f.read()
        print("🔐 AES key loaded.")
    return key

def encrypt_credentials(email, password, file_name, key):
    """Encrypt a single email/password pair into a .enc file."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    credentials = json.dumps({"email": email, "password": password}).encode()
    encrypted = aesgcm.encrypt(nonce, credentials, None)
    with open(file_name, "wb") as f:
        f.write(nonce + encrypted)
    print(f"✅ Encrypted and saved as: {file_name}")

# ✅ List your Grass accounts here
accounts = [
    {"email": "milly24@gmail.com", "password": "lookatmemen1", "file": "account1.enc"},
    {"email": "sanjimilton@gmail.com", "password": "lookatmemen1", "file": "account2.enc"},
]

# Generate or load encryption key
key = generate_key()

# Encrypt each account
for acc in accounts:
    encrypt_credentials(acc["email"], acc["password"], acc["file"], key)

# Create or update accounts.json for the bot to read
account_files = [acc["file"] for acc in accounts]
with open("accounts.json", "w") as f:
    json.dump(account_files, f, indent=2)

print("📄 accounts.json created/updated successfully.")
