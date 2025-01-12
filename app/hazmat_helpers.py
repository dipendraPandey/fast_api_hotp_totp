""" Opt builder classes."""
"""Cryptography Hazardous Materials helper functions."""
import random
from string import ascii_uppercase
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.fernet import Fernet
from typing import Any
import time
from cryptography.hazmat.primitives.twofactor import InvalidToken


def generate_random_character()->tuple[str, int]:
    character = random.choice(ascii_uppercase)
    return character, ord(character)

def get_hotp(key:bytes, length:int=6)->HOTP:
    try:
        return HOTP(key=key, length=length, algorithm=hashes.SHA512())
    except ValueError  as error:
        # logger.error(str(error))
        raise error
    except TypeError as error:
        # logger.error(str(error))
        raise ValueError("Invalid Algorithm.")


def get_totp(key:bytes, length:int=6, time_step:int=30)->TOTP:
    try:
        return TOTP(key=key, length=length, algorithm=hashes.SHA512(), time_step=time_step)
    except ValueError  as error:
        # logger.error(str(error))
        raise ValueError("Invalid length or Invalid key.")
    except TypeError as error:
        # logger.error(str(error))
        raise ValueError("Invalid Algorithm.")



def verify_totp(totp:TOTP, value:bytes, time_value:int):
    return totp.verify(value, time_value)

class HOTPBuilder:
    def __init__(self, key:bytes, counter:int=0, length:int=6):
        self.counter = counter
        self.hotp = get_hotp(key=key, length=length)
        self.key_builder = KeyBuilder()

    def generate_counter(self):
        character, counter = generate_random_character()
        self.counter = counter
        self.character = character
        return self.counter

    def get_key(self):
        if not self.key:
            self.key = self.key_builder.get_key()
        return self.key


    def generate(self)->tuple[str, int]:
        self.generate_counter()
        otp= self.hotp.generate(self.counter)
        hotp = self.character + otp.decode('utf-8')
        return hotp, self.counter

    def verify(self, hotp:str)->bool:
        otp = bytes(hotp[1:], 'utf-8')
        if self.counter ==0:
            raise ValueError("Invalid counter key.")
        try:
            return self.hotp.generate(counter=self.counter) == otp
        except InvalidToken as error:
            raise error


class TOTPBuilder:
    def __init__(self, key:bytes, length:int=6, time_step:int=30, time_value:float=time.time(),):
        self.key=key
        self.time_value = time_value
        self.totp = get_totp(key=key, length=length, time_step=time_step)
        self.key_builder = KeyBuilder()

    def generate(self)->tuple[str, float]:
        otp_value =  self.totp.generate(self.time_value)
        return otp_value.decode('utf-8'), self.time_value

    def get_key(self):
        if not self.key:
            self.key = self.key_builder.get_key()
        return self.key

    def verify(self, otp:str)-> bool:
        otp_bytes = bytes(otp, 'utf-8')
        try:
            self.totp.verify(totp=otp_bytes, time=int(self.time_value))
            return True
        except InvalidToken as e:
            # logger.error(str(e))
            return False


class KeyBuilder:
    def __init__(
        self,
        backend:Any= None)-> None:
        self.key = Fernet.generate_key()

    def get_key(self)-> bytes:
        return self.key
