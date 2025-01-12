from fastapi import FastAPI, HTTPException
import time
from pydantic import BaseModel
from typing import Dict, Optional
from fastapi.security import HTTPBearer
from app.models import *
from app.hazmat_helpers import BuildHOTP, KeyBuilder, BuildTOTP


app = FastAPI(title="Authentication API")
security = HTTPBearer()

user_secrets: Dict[str, Dict[str, str]] = {}

@app.post("/register", response_model=Dict[str, str])
async def register_user(user: UserRegistration):
    """Register a new user and generate their secret key."""
    if user.user_id in user_secrets:
        raise HTTPException(status_code=400, detail="User already registered")

    secret_key = KeyBuilder()
    key = secret_key.get_key()
    user_secrets[user.user_id] = {"secret_key":key}

    return {
        "user_id": user.user_id,
    }

@app.post("/generate/totp", response_model=OTPResponse)
async def generate_totp(user: UserRegistration):
    """Generate a TOTP for a registered user."""
    if user.user_id not in user_secrets:
        raise HTTPException(status_code=404, detail="User not found")

    secret_key = user_secrets[user.user_id]["secret_key"]
    time_value  =  time.time()
    user_secrets[user.user_id]['counter']= time_value
    totp_builder = BuildTOTP(key=secret_key, time_value=time_value)
    totp = totp_builder.generate()
    return OTPResponse(otp=totp)

@app.post("/generate/hotp", response_model=OTPResponse)
async def generate_hotp(user: UserRegistration):
    """Generate a HOTP for a registered user with a specific counter."""
    if user.user_id not in user_secrets:
        raise HTTPException(status_code=404, detail="User not found")

    secret_key = user_secrets[user.user_id]["secret_key"]
    hotp_builder = BuildHOTP(key=secret_key)
    hotp, counter = hotp_builder.generate()
    user_secrets[user.user_id]['counter']= counter

    return OTPResponse(otp=str(hotp))

@app.post("/verify/totp", response_model=VerificationResponse)
async def verify_totp(verification: OTPVerification):
    """Verify a TOTP."""
    if verification.user_id not in user_secrets:
        raise HTTPException(status_code=404, detail="User not found")

    secret_key = user_secrets[verification.user_id]["secret_key"]
    time_value = user_secrets[verification.user_id]["counter"]
    totp_builder = BuildTOTP(key=secret_key, time_value=time_value)
    is_valid = totp_builder.verify(otp=verification.otp)
    return VerificationResponse(is_valid=is_valid)

@app.post("/verify/hotp", response_model=VerificationResponse)
async def verify_hotp(verification: OTPVerification):
    """Verify a HOTP."""
    if verification.counter is None:
        raise HTTPException(status_code=400, detail="Counter is required for HOTP verification")

    if verification.user_id not in user_secrets:
        raise HTTPException(status_code=404, detail="User not found")
    user_value_dict = user_secrets[verification.user_id]
    secret_key = user_value_dict["secret_key"]
    counter = user_value_dict ["counter"]
    hotp_builder = BuildHOTP(key=secret_key, counter=counter)
    is_valid = hotp_builder.verifier(hotp=verification.otp)
    return VerificationResponse(is_valid=is_valid)
