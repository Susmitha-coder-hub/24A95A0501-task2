from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Dict
import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp
import hashlib
import time
import re

DATA_PATH = "/data/seed.txt"      # persistent file path required by task
PRIVATE_KEY_PATH = "student_private.pem"  # path in repo/container

app = FastAPI(title="TOTP Auth Microservice")

hex64_re = re.compile(r'^[0-9a-fA-F]{64}$')

class EncryptedSeedIn(BaseModel):
    encrypted_seed: str

class VerifyIn(BaseModel):
    code: str

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def decrypt_seed_b64(encrypted_b64: str, private_key):
    try:
        ciphertext = base64.b64decode(encrypted_b64)
    except Exception as e:
        raise ValueError("Invalid base64")
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext  # bytes
    except Exception as e:
        raise ValueError("Decryption failed")

def save_seed(hex_seed_str: str):
    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    with open(DATA_PATH, "w") as f:
        f.write(hex_seed_str)

def read_seed_hex() -> str:
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError("Seed not decrypted yet")
    with open(DATA_PATH, "r") as f:
        return f.read().strip()

def hex_to_base32_no_padding(hex_seed: str) -> str:
    raw = bytes.fromhex(hex_seed)
    b32 = base64.b32encode(raw).decode('utf-8').strip('=')
    return b32

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(payload: EncryptedSeedIn):
    # Load private key
    try:
        private_key = load_private_key(PRIVATE_KEY_PATH)
    except Exception as e:
        # Private key missing or invalid
        raise HTTPException(status_code=500, detail={"error": "Private key not found or invalid"})

    # Decrypt
    try:
        plaintext = decrypt_seed_b64(payload.encrypted_seed, private_key)
    except ValueError:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

    # plaintext expected to be ASCII hex
    try:
        hex_str = plaintext.decode("utf-8").strip()
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

    # Validate 64-character hex
    if not hex64_re.match(hex_str):
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

    # Save persistently
    try:
        save_seed(hex_str)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Failed to save seed"})

    return {"status": "ok"}

@app.get("/generate-2fa")
def generate_2fa():
    # Ensure seed present
    try:
        hex_seed = read_seed_hex()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    # Generate totp
    try:
        base32_seed = hex_to_base32_no_padding(hex_seed)
        totp = pyotp.TOTP(base32_seed, digits=6, interval=30, digest=hashlib.sha1)
        code = totp.now()
        # compute valid_for seconds left in current 30s window
        step = 30
        now = int(time.time())
        valid_for = step - (now % step)
        return {"code": code, "valid_for": valid_for}
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "TOTP generation failed"})

@app.post("/verify-2fa")
def verify_2fa(payload: VerifyIn):
    if not payload.code or payload.code.strip() == "":
        raise HTTPException(status_code=400, detail={"error": "Missing code"})

    # Ensure seed present
    try:
        hex_seed = read_seed_hex()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    try:
        base32_seed = hex_to_base32_no_padding(hex_seed)
        totp = pyotp.TOTP(base32_seed, digits=6, interval=30, digest=hashlib.sha1)
        valid = totp.verify(payload.code, valid_window=1)
        return {"valid": bool(valid)}
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Verification failed"})
