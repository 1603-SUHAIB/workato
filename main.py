from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from Crypto.Cipher import AES
import json
import base64
import os
import random

app = FastAPI()

# AES key must be 16, 24, or 32 bytes long (AES-128, AES-192, AES-256)
AES_KEY = os.environ.get("AES_KEY") or b"mysecretkey12345"  # 16 bytes

# Padding functions
def pad(s):
    pad_len = 16 - (len(s) % 16)
    return s + chr(pad_len) * pad_len

def unpad(s):
    return s[:-ord(s[-1])]

# Request models
class EncryptRequest(BaseModel):
    data: dict

class DecryptRequest(BaseModel):
    encrypted_data: str
    otp: str

@app.post("/encrypt")
def encrypt_data(req: EncryptRequest):
    try:
        otp = str(random.randint(1000, 9999))
        data_with_otp = req.data.copy()
        data_with_otp["otp"] = otp

        raw = json.dumps(data_with_otp)
        padded = pad(raw)

        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(padded.encode())
        encoded = base64.urlsafe_b64encode(encrypted).decode()

        return {
            "encrypted_data": encoded,
            "otp": otp  # For testing/demo; remove in production
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/decrypt")
def decrypt_data(req: DecryptRequest):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        decoded = base64.urlsafe_b64decode(req.encrypted_data.encode())
        decrypted = cipher.decrypt(decoded).decode()
        data = json.loads(unpad(decrypted))

        if req.otp != data.get("otp"):
            return {"status": "failure", "message": "OTP mismatch"}

        data.pop("otp", None)
        return {"status": "success", "data": data}
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid encrypted data or OTP")
