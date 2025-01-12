from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
import base64
import time
import struct

class OTPGenerator:
    def __init__(self, secret_key: str):
        """Initialize the OTP generator with a secret key.

        Args:
            secret_key (str): Base32 encoded secret key
        """
        # Decode the base32 secret key
        self.secret_key = base64.b32decode(secret_key.upper() + '=' * ((8 - len(secret_key)) % 8))

    def generate_hotp(self, counter: int, digits: int = 6) -> str:
        """Generate an HOTP value using SHA-512.

        Args:
            counter (int): The counter value
            digits (int): Number of digits in the OTP (default: 6)

        Returns:
            str: The generated HOTP value
        """
        # Create an HMAC object with SHA-512
        hmac = HMAC(self.secret_key, hashes.SHA512())

        # Convert counter to bytes (8-byte, big-endian)
        counter_bytes = struct.pack('>Q', counter)

        # Update HMAC with counter
        hmac.update(counter_bytes)

        # Get the HMAC digest
        hmac_result = hmac.finalize()

        # Get offset - use last byte of SHA-512 hash
        offset = hmac_result[-1] & 0xf

        # Generate 4-byte code
        code = ((hmac_result[offset] & 0x7f) << 24 |
                (hmac_result[offset + 1] & 0xff) << 16 |
                (hmac_result[offset + 2] & 0xff) << 8 |
                (hmac_result[offset + 3] & 0xff))

        # Generate OTP
        otp = str(code % (10 ** digits))

        # Pad with leading zeros if necessary
        return otp.zfill(digits)

    def generate_totp(self, time_step: int = 30, digits: int = 6) -> str:
        """Generate a TOTP value.

        Args:
            time_step (int): Time step in seconds (default: 30)
            digits (int): Number of digits in the OTP (default: 6)

        Returns:
            str: The generated TOTP value
        """
        # Get current timestamp
        timestamp = int(time.time())

        # Calculate counter value
        counter = timestamp // time_step

        return self.generate_hotp(counter, digits)

    def verify_hotp(self, otp: str, counter: int, digits: int = 6) -> bool:
        """Verify an HOTP value.

        Args:
            otp (str): The OTP to verify
            counter (int): The counter value
            digits (int): Number of digits in the OTP (default: 6)

        Returns:
            bool: True if OTP is valid, False otherwise
        """
        return self.generate_hotp(counter, digits) == otp

    def verify_totp(self, otp: str, time_step: int = 30, digits: int = 6,
                    allowed_time_drift: int = 1) -> bool:
        """Verify a TOTP value with allowed time drift.

        Args:
            otp (str): The OTP to verify
            time_step (int): Time step in seconds (default: 30)
            digits (int): Number of digits in the OTP (default: 6)
            allowed_time_drift (int): Number of time steps to allow for drift (default: 1)

        Returns:
            bool: True if OTP is valid, False otherwise
        """
        timestamp = int(time.time())
        counter = timestamp // time_step

        # Check current and adjacent time steps
        for i in range(-allowed_time_drift, allowed_time_drift + 1):
            if self.generate_hotp(counter + i, digits) == otp:
                return True

        return False

def generate_secret_key(length: int = 64) -> str:
    """Generate a random secret key.

    Args:
        length (int): Length of the secret key in bytes (default: 64 for SHA-512)

    Returns:
        str: Base32 encoded secret key
    """
    import os
    secret = os.urandom(length)
    return base64.b32encode(secret).decode('utf-8')
