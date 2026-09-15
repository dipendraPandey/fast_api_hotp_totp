
from pydantic import BaseModel

class UserRegistration(BaseModel):
    user_id: str

class RegisterUserRequest(BaseModel):
    user_id: str
    password: str

class UserLogin(BaseModel):
    user_id: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str

class TokenRefresh(BaseModel):
    refresh_token: str

class OTPVerification(BaseModel):
    user_id: str
    otp: str

class OTPResponse(BaseModel):
    otp: str

class VerificationResponse(BaseModel):
    is_valid: bool
