"""Unit of Work implementation."""
import abc
from typing import Generator, List
from app.adapters.repository import AbstractUserRepository, InMemoryUserRepository
from app.domain.events import Event

class AbstractUnitOfWork(abc.ABC):
    users: AbstractUserRepository

    def __enter__(self) -> "AbstractUnitOfWork":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()

    def commit(self):
        self._commit()

    def collect_new_events(self) -> Generator[Event, None, None]:
        for user in self.users.seen:
            while user.events:
                yield user.events.pop(0)

    @abc.abstractmethod
    def _commit(self):
        raise NotImplementedError

    @abc.abstractmethod
    def rollback(self):
        raise NotImplementedError


# Global shared in-memory database dictionary for demo/runtime persistence across UoWs
DEFAULT_IN_MEMORY_USERS_DB = {}

class InMemoryUnitOfWork(AbstractUnitOfWork):
    def __init__(self, db: dict = DEFAULT_IN_MEMORY_USERS_DB):
        self.db = db
        self.committed = False

    def __enter__(self) -> "InMemoryUnitOfWork":
        self.users = InMemoryUserRepository(self.db)
        self.committed = False
        return super().__enter__()

    def _commit(self):
        self.committed = True

    def rollback(self):
        pass
