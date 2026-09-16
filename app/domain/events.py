"""Domain events."""
from dataclasses import dataclass

@dataclass
class Event:
    pass

@dataclass
class UserRegistered(Event):
    user_id: str

@dataclass
class TOTPGenerated(Event):
    user_id: str

@dataclass
class HOTPGenerated(Event):
    user_id: str
    counter: int

@dataclass
class TOTPVerified(Event):
    user_id: str
    is_valid: bool

@dataclass
class HOTPVerified(Event):
    user_id: str
    is_valid: bool
