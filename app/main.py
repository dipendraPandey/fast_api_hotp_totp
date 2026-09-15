from fastapi import FastAPI, HTTPException, Depends
import time
from pydantic import BaseModel
from typing import Dict, Optional
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.models import *
from app.hazmat_helpers import TOTPBuilder, KeyBuilder, HOTPBuilder
from app.jwt_helpers import get_password_hash, verify_password, create_access_token, create_refresh_token, verify_jwt_token, ACCESS_TOKEN_EXPIRE_MINUTES
from datetime import timedelta
from jose import JWTError

app = FastAPI(title="Authentication API")
security = HTTPBearer()

user_secrets: Dict[str, Dict[str, str]] = {}

@app.post("/register", response_model=Dict[str, str])
async def register_user(user: RegisterUserRequest):
    """Register a new user and generate their secret key and hash their password."""
    if user.user_id in user_secrets:
        raise HTTPException(status_code=400, detail="User already registered")

    secret_key = KeyBuilder()
    key = secret_key.get_key()

    hashed_password = get_password_hash(user.password)

    user_secrets[user.user_id] = {
        "secret_key": key,
        "password": hashed_password
    }

    return {
        "user_id": user.user_id,
    }

@app.post("/login", response_model=TokenResponse)
async def login_user(user: UserLogin):
    """Login and receive a JWT token (Base64 encoded)."""
    if user.user_id not in user_secrets:
        raise HTTPException(status_code=400, detail="Incorrect user_id or password")

    hashed_password = user_secrets[user.user_id]["password"]
    if not verify_password(user.password, hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect user_id or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.user_id}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        data={"sub": user.user_id}
    )

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)

@app.post("/refresh", response_model=TokenResponse)
async def refresh_token(token_data: TokenRefresh):
    """Refresh the access token using a refresh token."""
    try:
        payload = verify_jwt_token(token_data.refresh_token, expected_type="refresh")
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    if user_id not in user_secrets:
        raise HTTPException(status_code=404, detail="User not found")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_id}, expires_delta=access_token_expires
    )
    # Return the same refresh token, or create a new one. Here we return the same.
    # Alternatively we can rotate refresh tokens.
    new_refresh_token = create_refresh_token(data={"sub": user_id})
    return TokenResponse(access_token=access_token, refresh_token=new_refresh_token)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = verify_jwt_token(credentials.credentials)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if user_id not in user_secrets:
        raise HTTPException(status_code=401, detail="User not found")

    return user_id

@app.get("/protected")
async def protected_route(user_id: str = Depends(get_current_user)):
    """A route protected by JWT authentication."""
    return {"message": "You are authenticated", "user_id": user_id}

@app.post("/generate/totp", response_model=OTPResponse)
async def generate_totp(user: UserRegistration):
    """Generate a TOTP for a registered user."""
    if user.user_id not in user_secrets:
        raise HTTPException(status_code=404, detail="User not found")

    secret_key = user_secrets[user.user_id]["secret_key"]
    time_value  =  time.time()
    user_secrets[user.user_id]['counter']= time_value
    totp_builder = TOTPBuilder(key=secret_key, time_value=time_value)
    totp, time_value = totp_builder.generate()
    return OTPResponse(otp=totp)

@app.post("/generate/hotp", response_model=OTPResponse)
async def generate_hotp(user: UserRegistration):
    """Generate a HOTP for a registered user with a specific counter."""
    if user.user_id not in user_secrets:
        raise HTTPException(status_code=404, detail="User not found")

    secret_key = user_secrets[user.user_id]["secret_key"]
    hotp_builder = HOTPBuilder(key=secret_key)
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
    totp_builder = TOTPBuilder(key=secret_key, time_value=time_value)
    is_valid = totp_builder.verify(otp=verification.otp)
    return VerificationResponse(is_valid=is_valid)

@app.post("/verify/hotp", response_model=VerificationResponse)
async def verify_hotp(verification: OTPVerification):
    """Verify a HOTP."""

    if verification.user_id not in user_secrets:
        raise HTTPException(status_code=404, detail="User not found")
    user_value_dict = user_secrets[verification.user_id]
    secret_key = user_value_dict["secret_key"]
    counter = user_value_dict ["counter"]
    hotp_builder = HOTPBuilder(key=secret_key, counter=counter)
    is_valid = hotp_builder.verify(hotp=verification.otp)
    return VerificationResponse(is_valid=is_valid)
