from fastapi import FastAPI, HTTPException
import time
from pydantic import BaseModel
from typing import Dict, Optional
from fastapi.security import HTTPBearer
from app.models import *
from app.hazmat_helpers import TOTPBuilder, KeyBuilder, HOTPBuilder


from contextlib import asynccontextmanager
import httpx
import os

http_client = None
opa_url = os.environ.get("OPA_URL", "http://localhost:8181/v1/data/app/rbac/allow")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    http_client = httpx.AsyncClient(timeout=5.0)
    yield
    if http_client:
        await http_client.aclose()

app = FastAPI(title="Authentication API", lifespan=lifespan)
security = HTTPBearer()

user_secrets: Dict[str, Dict[str, str]] = {}

def verify_permission(action: str, resource_type: str):
    async def dependency(user_id: str):
        global http_client
        # We need the user to be passed. Assuming it comes from a query parameter for the mock,
        # or header in a real scenario.
        if not http_client:
            raise HTTPException(status_code=503, detail="Service Unavailable: HTTP client not initialized")

        payload = {
            "input": {
                "user": user_id,
                "action": action,
                "resource": resource_type
            }
        }
        try:
            response = await http_client.post(opa_url, json=payload, timeout=2.0)
            response.raise_for_status()
            result = response.json()
            if not result.get("result", False):
                raise HTTPException(status_code=403, detail="Forbidden")
        except httpx.RequestError as e:
            # Cannot reach OPA
            raise HTTPException(status_code=503, detail="Service Unavailable: Authorization service unreachable")
        return user_id
    return dependency

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


from fastapi import Depends

@app.get("/finance/{report_id}")
async def get_finance_report(
    report_id: str,
    user_id: str = Depends(verify_permission(action="read", resource_type="finance"))
):
    """A mock protected endpoint requiring 'read' permission on 'finance' resource."""
    return {"report_id": report_id, "data": "Confidential financial data", "accessed_by": user_id}
