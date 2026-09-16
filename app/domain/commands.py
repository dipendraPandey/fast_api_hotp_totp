"""Domain commands."""
from dataclasses import dataclass

@dataclass
class Command:
    pass

@dataclass
class RegisterUserCommand(Command):
    user_id: str
    password: str

@dataclass
class LoginUserCommand(Command):
    user_id: str
    password: str

@dataclass
class RefreshTokenCommand(Command):
    refresh_token: str

@dataclass
class GenerateTOTPCommand(Command):
    user_id: str

@dataclass
class GenerateHOTPCommand(Command):
    user_id: str

@dataclass
class VerifyTOTPCommand(Command):
    user_id: str
    otp: str

@dataclass
class VerifyHOTPCommand(Command):
    user_id: str
    otp: str
