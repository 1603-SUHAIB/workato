from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.fernet import Fernet
import json
import os
import random

app = FastAPI()

# Generate and store a key securely for production
FERNET_KEY = os.environ.get("FERNET_KEY") or Fernet.generate_key().decode()
fernet = Fernet(FERNET_KEY.encode())

class EncryptRequest(BaseModel):
    data: dict

class DecryptRequest(BaseModel):
    encrypted_data: str
    otp: str

@app.post("/encrypt")
def encrypt_data(req: EncryptRequest):
    try:
        # Generate 4-digit OTP
        otp = str(random.randint(1000, 9999))

        # Add OTP inside data before encryption
        data_with_otp = req.data.copy()
        data_with_otp["otp"] = otp

        # Encrypt entire payload
        raw_data = json.dumps(data_with_otp)
        encrypted_data = fernet.encrypt(raw_data.encode()).decode()

        return {
            "encrypted_data": encrypted_data,
            "otp": otp  # only for testing; remove in production
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/decrypt")
def decrypt_data(req: DecryptRequest):
    try:
        # Decrypt data
        decrypted_bytes = fernet.decrypt(req.encrypted_data.encode())
        decrypted_str = decrypted_bytes.decode()
        decrypted_data = json.loads(decrypted_str)

        # Verify OTP
        original_otp = decrypted_data.get("otp")
        if req.otp != original_otp:
            return {"status": "failure", "message": "OTP verification failed"}

        # Remove OTP before returning
        decrypted_data.pop("otp", None)
        return {"status": "success", "data": decrypted_data}

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid encrypted data or OTP")
