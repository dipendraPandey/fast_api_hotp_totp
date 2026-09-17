"""UserRepository implementation following Repository Pattern."""
import abc
from typing import Dict, Optional, Set
from app.domain.models import User

class AbstractUserRepository(abc.ABC):
    def __init__(self):
        self.seen: Set[User] = set()

    def add(self, user: User) -> None:
        self._add(user)
        self.seen.add(user)

    def get(self, user_id: str) -> Optional[User]:
        user = self._get(user_id)
        if user:
            self.seen.add(user)
        return user

    @abc.abstractmethod
    def _add(self, user: User) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def _get(self, user_id: str) -> Optional[User]:
        raise NotImplementedError

class InMemoryUserRepository(AbstractUserRepository):
    def __init__(self, users_dict: Optional[Dict[str, User]] = None):
        super().__init__()
        self._users: Dict[str, User] = users_dict if users_dict is not None else {}

    def _add(self, user: User) -> None:
        self._users[user.user_id] = user

    def _get(self, user_id: str) -> Optional[User]:
        return self._users.get(user_id)
