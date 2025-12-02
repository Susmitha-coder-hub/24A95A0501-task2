from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp
import hashlib
import time
import re

# -------------------- Config --------------------
DATA_PATH = "/data/seed.txt"             # persistent file path
PRIVATE_KEY_PATH = "student_private.pem" # path to RSA private key

hex64_re = re.compile(r'^[0-9a-fA-F]{64}$')

app = FastAPI(title="TOTP Auth Microservice")

# -------------------- Pydantic Models --------------------
class EncryptedSeedIn(BaseModel):
    encrypted_seed: str

class VerifyIn(BaseModel):
    code: str

# -------------------- Utility Functions --------------------
def load_private_key(path: str):
    """Load RSA private key from PEM file."""
    if not os.path.exists(path):
        raise FileNotFoundError("Private key not found")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def decrypt_seed_b64(encrypted_b64: str, private_key):
    """Decrypt Base64-encoded encrypted seed using RSA/OAEP-SHA256."""
    try:
        ciphertext = base64.b64decode(encrypted_b64)
    except Exception:
        raise ValueError("Invalid base64 encoding")

    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    except Exception:
        raise ValueError("Decryption failed")

def save_seed(hex_seed_str: str):
    """Persist the decrypted seed to disk."""
    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    with open(DATA_PATH, "w") as f:
        f.write(hex_seed_str)

def read_seed_hex() -> str:
    """Read the stored seed from disk."""
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError("Seed not decrypted yet")
    with open(DATA_PATH, "r") as f:
        return f.read().strip()

def hex_to_base32_no_padding(hex_seed: str) -> str:
    """Convert hex seed to Base32 without padding for pyotp."""
    raw = bytes.fromhex(hex_seed)
    b32 = base64.b32encode(raw).decode('utf-8').strip('=')
    return b32

# -------------------- API Endpoints --------------------

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(payload: EncryptedSeedIn):
    # Load private key
    try:
        private_key = load_private_key(PRIVATE_KEY_PATH)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Private key not found or invalid"})

    # Decrypt seed
    try:
        plaintext = decrypt_seed_b64(payload.encrypted_seed, private_key)
        hex_str = plaintext.decode("utf-8").strip()
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

    # Validate 64-character hex
    if not hex64_re.match(hex_str):
        raise HTTPException(status_code=500, detail={"error": "Decryption failed: Invalid hex format"})

    # Save persistently
    try:
        save_seed(hex_str)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Failed to save seed"})

    return {"status": "ok"}


@app.get("/generate-2fa")
def generate_2fa():
    """Generate current 6-digit TOTP code."""
    try:
        hex_seed = read_seed_hex()
        base32_seed = hex_to_base32_no_padding(hex_seed)
        totp = pyotp.TOTP(base32_seed, digits=6, interval=30, digest=hashlib.sha1)
        code = totp.now()
        step = 30
        now = int(time.time())
        valid_for = step - (now % step)
        return {"code": code, "valid_for": valid_for}
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "TOTP generation failed"})


@app.post("/verify-2fa")
def verify_2fa(payload: VerifyIn):
    """Verify a provided TOTP code."""
    if not payload.code.strip():
        raise HTTPException(status_code=400, detail={"error": "Missing code"})

    try:
        hex_seed = read_seed_hex()
        base32_seed = hex_to_base32_no_padding(hex_seed)
        totp = pyotp.TOTP(base32_seed, digits=6, interval=30, digest=hashlib.sha1)
        valid = totp.verify(payload.code, valid_window=1)
        return {"valid": bool(valid)}
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Verification failed"})
