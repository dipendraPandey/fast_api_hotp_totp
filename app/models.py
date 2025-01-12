
from pydantic import BaseModel
class UserRegistration(BaseModel):
    user_id: str

class OTPVerification(BaseModel):
    user_id: str
    otp: str

class OTPResponse(BaseModel):
    otp: str

class VerificationResponse(BaseModel):
    is_valid: bool
