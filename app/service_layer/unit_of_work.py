"""Unit of Work implementation."""
import abc
import os
from typing import Generator, List
from sqlmodel import SQLModel, Session, create_engine
from app.adapters.repository import (
    AbstractUserRepository,
    InMemoryUserRepository,
    SqlModelUserRepository,
)
from app.domain.events import Event

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./sqlite.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


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


class SqlModelUnitOfWork(AbstractUnitOfWork):
    def __init__(self, session_factory=None):
        self.session_factory = session_factory or (lambda: Session(engine))

    def __enter__(self) -> "SqlModelUnitOfWork":
        self.session: Session = self.session_factory()
        self.users = SqlModelUserRepository(self.session)
        return super().__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        super().__exit__(exc_type, exc_val, exc_tb)
        self.session.close()

    def _commit(self):
        self.users.add_all(self.users.seen)
        self.session.commit()

    def rollback(self):
        self.session.rollback()
