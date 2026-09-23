import pytest
import pytest_asyncio
from app.domain import commands, events
from app.domain.models import User
from app.service_layer.unit_of_work import InMemoryUnitOfWork
from app.service_layer.messagebus import MessageBus

def test_user_aggregate_events():
    user = User.register("alice", "password123")
    assert len(user.events) == 1
    assert isinstance(user.events[0], events.UserRegistered)

    totp = user.generate_totp()
    assert len(user.events) == 2
    assert isinstance(user.events[1], events.TOTPGenerated)
    assert user.verify_totp(totp) is True


def test_user_generate_and_verify_hotp():
    user = User.register("alice", "password123")
    assert user.counter == 0

    hotp = user.generate_hotp()
    assert isinstance(hotp, str)
    assert len(hotp) == 7
    assert user.counter > 0
    assert len(user.events) == 2
    assert isinstance(user.events[1], events.HOTPGenerated)
    assert user.events[1].user_id == "alice"
    assert user.events[1].counter == user.counter

    assert user.verify_hotp(hotp) is True
    assert len(user.events) == 3
    assert isinstance(user.events[2], events.HOTPVerified)
    assert user.events[2].user_id == "alice"
    assert user.events[2].is_valid is True

def test_messagebus_command_and_event_handling():
    uow = InMemoryUnitOfWork(db={})
    handled_events = []

    def dummy_event_handler(event: events.Event):
        handled_events.append(event)

    bus = MessageBus(
        uow=uow,
        event_handlers={events.UserRegistered: [dummy_event_handler]}
    )

    cmd = commands.RegisterUserCommand(user_id="bob", password="password123")
    res = bus.handle(cmd)

    assert res == {"user_id": "bob"}
    assert len(handled_events) == 1
    assert isinstance(handled_events[0], events.UserRegistered)
    assert handled_events[0].user_id == "bob"
