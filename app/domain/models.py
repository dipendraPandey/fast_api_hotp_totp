"""Domain aggregate models."""
import time
from typing import List, Optional
from app.domain.events import (
    Event,
    UserRegistered,
    TOTPGenerated,
    HOTPGenerated,
    TOTPVerified,
    HOTPVerified,
)
from app.hazmat_helpers import TOTPBuilder, KeyBuilder, HOTPBuilder
from app.jwt_helpers import get_password_hash, verify_password


class User:
    def __init__(
        self,
        user_id: str,
        password_hash: str,
        secret_key: Optional[bytes] = None,
        counter: Optional[float] = None,
    ):
        self.user_id = user_id
        self.password_hash = password_hash
        self.secret_key = secret_key or KeyBuilder().get_key()
        self.counter = counter if counter is not None else 0
        self.events: List[Event] = []

    @classmethod
    def register(cls, user_id: str, password: str) -> "User":
        hashed_password = get_password_hash(password)
        secret_key = KeyBuilder().get_key()
        user = cls(user_id=user_id, password_hash=hashed_password, secret_key=secret_key)
        user.events.append(UserRegistered(user_id=user_id))
        return user

    def verify_password(self, password: str) -> bool:
        return verify_password(password, self.password_hash)

    def generate_totp(self) -> str:
        time_value = time.time()
        self.counter = time_value
        totp_builder = TOTPBuilder(key=self.secret_key, time_value=time_value)
        totp, _ = totp_builder.generate()
        self.events.append(TOTPGenerated(user_id=self.user_id))
        return totp

    def generate_hotp(self) -> str:
        hotp_builder = HOTPBuilder(key=self.secret_key)
        hotp, counter = hotp_builder.generate()
        self.counter = counter
        self.events.append(HOTPGenerated(user_id=self.user_id, counter=counter))
        return str(hotp)

    def verify_totp(self, otp: str) -> bool:
        totp_builder = TOTPBuilder(key=self.secret_key, time_value=self.counter)
        is_valid = totp_builder.verify(otp=otp)
        self.events.append(TOTPVerified(user_id=self.user_id, is_valid=is_valid))
        return is_valid

    def verify_hotp(self, otp: str) -> bool:
        hotp_builder = HOTPBuilder(key=self.secret_key, counter=int(self.counter))
        is_valid = hotp_builder.verify(hotp=otp)
        self.events.append(HOTPVerified(user_id=self.user_id, is_valid=is_valid))
        return is_valid
