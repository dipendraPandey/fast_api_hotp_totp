"""Command and Event Handlers."""
from datetime import timedelta
import logging
from jose import JWTError
from app.domain import commands, events
from app.domain.models import User
from app.jwt_helpers import (
    create_access_token,
    create_refresh_token,
    verify_jwt_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from app.service_layer.unit_of_work import AbstractUnitOfWork

logger = logging.getLogger(__name__)

class InvalidCredentialsException(Exception):
    pass

class UserAlreadyExistsException(Exception):
    pass

class UserNotFoundException(Exception):
    pass

class InvalidTokenException(Exception):
    pass

# Command Handlers

def register_user(
    cmd: commands.RegisterUserCommand, uow: AbstractUnitOfWork
) -> dict:
    with uow:
        existing = uow.users.get(cmd.user_id)
        if existing:
            raise UserAlreadyExistsException("User already registered")
        user = User.register(user_id=cmd.user_id, password=cmd.password)
        uow.users.add(user)
        uow.commit()
        return {"user_id": user.user_id}

def login_user(
    cmd: commands.LoginUserCommand, uow: AbstractUnitOfWork
) -> dict:
    with uow:
        user = uow.users.get(cmd.user_id)
        if not user or not user.verify_password(cmd.password):
            raise InvalidCredentialsException("Incorrect user_id or password")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.user_id}, expires_delta=access_token_expires
        )
        refresh_token = create_refresh_token(data={"sub": user.user_id})
        return {"access_token": access_token, "refresh_token": refresh_token}

def refresh_token(
    cmd: commands.RefreshTokenCommand, uow: AbstractUnitOfWork
) -> dict:
    try:
        payload = verify_jwt_token(cmd.refresh_token, expected_type="refresh")
        user_id: str = payload.get("sub")
        if user_id is None:
            raise InvalidTokenException("Invalid token")
    except JWTError:
        raise InvalidTokenException("Invalid or expired refresh token")

    with uow:
        user = uow.users.get(user_id)
        if not user:
            raise UserNotFoundException("User not found")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user_id}, expires_delta=access_token_expires
        )
        new_refresh_token = create_refresh_token(data={"sub": user_id})
        return {"access_token": access_token, "refresh_token": new_refresh_token}

def generate_totp(
    cmd: commands.GenerateTOTPCommand, uow: AbstractUnitOfWork
) -> dict:
    with uow:
        user = uow.users.get(cmd.user_id)
        if not user:
            raise UserNotFoundException("User not found")
        totp = user.generate_totp()
        uow.commit()
        return {"otp": totp}

def generate_hotp(
    cmd: commands.GenerateHOTPCommand, uow: AbstractUnitOfWork
) -> dict:
    with uow:
        user = uow.users.get(cmd.user_id)
        if not user:
            raise UserNotFoundException("User not found")
        hotp = user.generate_hotp()
        uow.commit()
        return {"otp": hotp}

def verify_totp(
    cmd: commands.VerifyTOTPCommand, uow: AbstractUnitOfWork
) -> dict:
    with uow:
        user = uow.users.get(cmd.user_id)
        if not user:
            raise UserNotFoundException("User not found")
        is_valid = user.verify_totp(cmd.otp)
        uow.commit()
        return {"is_valid": is_valid}

def verify_hotp(
    cmd: commands.VerifyHOTPCommand, uow: AbstractUnitOfWork
) -> dict:
    with uow:
        user = uow.users.get(cmd.user_id)
        if not user:
            raise UserNotFoundException("User not found")
        is_valid = user.verify_hotp(cmd.otp)
        uow.commit()
        return {"is_valid": is_valid}


# Event Handlers

def log_user_registered(event: events.UserRegistered):
    logger.info(f"User registered successfully: {event.user_id}")

def log_totp_generated(event: events.TOTPGenerated):
    logger.info(f"TOTP generated for user: {event.user_id}")

def log_hotp_generated(event: events.HOTPGenerated):
    logger.info(f"HOTP generated for user: {event.user_id} with counter {event.counter}")

COMMAND_HANDLERS = {
    commands.RegisterUserCommand: register_user,
    commands.LoginUserCommand: login_user,
    commands.RefreshTokenCommand: refresh_token,
    commands.GenerateTOTPCommand: generate_totp,
    commands.GenerateHOTPCommand: generate_hotp,
    commands.VerifyTOTPCommand: verify_totp,
    commands.VerifyHOTPCommand: verify_hotp,
}

EVENT_HANDLERS = {
    events.UserRegistered: [log_user_registered],
    events.TOTPGenerated: [log_totp_generated],
    events.HOTPGenerated: [log_hotp_generated],
}
