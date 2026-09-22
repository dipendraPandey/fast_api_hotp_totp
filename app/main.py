import os
from contextlib import asynccontextmanager
from typing import Dict
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
from jose import JWTError

from app.models import (
    UserRegistration,
    RegisterUserRequest,
    UserLogin,
    TokenResponse,
    TokenRefresh,
    OTPVerification,
    OTPResponse,
    VerificationResponse,
)
from app.domain import commands
from app.service_layer import handlers
from app.service_layer.messagebus import MessageBus
from app.container import resolve_message_bus
from app.jwt_helpers import verify_jwt_token
from app.service_layer.unit_of_work import SqlModelUnitOfWork, create_db_and_tables

http_client = None
opa_url = os.environ.get("OPA_URL", "http://localhost:8181/v1/data/app/rbac/allow")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    create_db_and_tables()
    http_client = httpx.AsyncClient(timeout=5.0)
    yield
    if http_client:
        await http_client.aclose()

app = FastAPI(title="Authentication API", lifespan=lifespan)
security = HTTPBearer()

async def get_bus() -> MessageBus:
    return await resolve_message_bus()

def verify_permission(action: str, resource_type: str):
    async def dependency(user_id: str):
        global http_client
        if not http_client:
            raise HTTPException(status_code=503, detail="Service Unavailable: HTTP client not initialized")

        payload = {
            "input": {
                "user": user_id,
                "action": action,
                "resource": resource_type
            }
        }
        headers = {}
        opa_token = os.environ.get("OPA_TOKEN") or os.environ.get("OPA_AUTH_TOKEN") or os.environ.get("OPA_BEARER_TOKEN")
        if opa_token:
            headers["Authorization"] = f"Bearer {opa_token}"

        try:
            response = await http_client.post(opa_url, json=payload, headers=headers, timeout=2.0)
            response.raise_for_status()
            result = response.json()
            if not result.get("result", False):
                raise HTTPException(status_code=403, detail="Forbidden")
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Service Unavailable: Authorization service unreachable")
        return user_id
    return dependency

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = verify_jwt_token(credentials.credentials)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    uow = SqlModelUnitOfWork()
    with uow:
        user = uow.users.get(user_id)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

    return user_id

@app.post("/register", response_model=Dict[str, str])
async def register_user(
    user: RegisterUserRequest, bus: MessageBus = Depends(get_bus)
):
    """Register a new user via RegisterUserCommand."""
    cmd = commands.RegisterUserCommand(user_id=user.user_id, password=user.password)
    try:
        result = bus.handle(cmd)
        return result
    except handlers.UserAlreadyExistsException as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login", response_model=TokenResponse)
async def login_user(
    user: UserLogin, bus: MessageBus = Depends(get_bus)
):
    """Login user via LoginUserCommand."""
    cmd = commands.LoginUserCommand(user_id=user.user_id, password=user.password)
    try:
        result = bus.handle(cmd)
        return TokenResponse(**result)
    except handlers.InvalidCredentialsException as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    token_data: TokenRefresh, bus: MessageBus = Depends(get_bus)
):
    """Refresh JWT token via RefreshTokenCommand."""
    cmd = commands.RefreshTokenCommand(refresh_token=token_data.refresh_token)
    try:
        result = bus.handle(cmd)
        return TokenResponse(**result)
    except handlers.InvalidTokenException as e:
        raise HTTPException(status_code=401, detail=str(e))
    except handlers.UserNotFoundException as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/protected")
async def protected_route(user_id: str = Depends(get_current_user)):
    """A route protected by JWT authentication."""
    return {"message": "You are authenticated", "user_id": user_id}

@app.post("/generate/totp", response_model=OTPResponse)
async def generate_totp(
    user: UserRegistration, bus: MessageBus = Depends(get_bus)
):
    """Generate TOTP via GenerateTOTPCommand."""
    cmd = commands.GenerateTOTPCommand(user_id=user.user_id)
    try:
        result = bus.handle(cmd)
        return OTPResponse(**result)
    except handlers.UserNotFoundException as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/generate/hotp", response_model=OTPResponse)
async def generate_hotp(
    user: UserRegistration, bus: MessageBus = Depends(get_bus)
):
    """Generate HOTP via GenerateHOTPCommand."""
    cmd = commands.GenerateHOTPCommand(user_id=user.user_id)
    try:
        result = bus.handle(cmd)
        return OTPResponse(**result)
    except handlers.UserNotFoundException as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/verify/totp", response_model=VerificationResponse)
async def verify_totp(
    verification: OTPVerification, bus: MessageBus = Depends(get_bus)
):
    """Verify TOTP via VerifyTOTPCommand."""
    cmd = commands.VerifyTOTPCommand(user_id=verification.user_id, otp=verification.otp)
    try:
        result = bus.handle(cmd)
        return VerificationResponse(**result)
    except handlers.UserNotFoundException as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/verify/hotp", response_model=VerificationResponse)
async def verify_hotp(
    verification: OTPVerification, bus: MessageBus = Depends(get_bus)
):
    """Verify HOTP via VerifyHOTPCommand."""
    cmd = commands.VerifyHOTPCommand(user_id=verification.user_id, otp=verification.otp)
    try:
        result = bus.handle(cmd)
        return VerificationResponse(**result)
    except handlers.UserNotFoundException as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/finance/{report_id}")
async def get_finance_report(
    report_id: str,
    user_id: str = Depends(verify_permission(action="read", resource_type="finance"))
):
    """A mock protected endpoint requiring 'read' permission on 'finance' resource."""
    return {"report_id": report_id, "data": "Confidential financial data", "accessed_by": user_id}
