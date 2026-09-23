"""UserRepository implementation following Repository Pattern."""
import abc
from typing import Dict, Iterable, Optional, Set
from sqlmodel import SQLModel, Field, Session, select
from app.domain.models import User


class UserModel(SQLModel, table=True):
    __tablename__ = "users"

    user_id: str = Field(primary_key=True)
    password_hash: str
    secret_key: bytes
    counter: float = Field(default=0.0)


class AbstractUserRepository(abc.ABC):
    def __init__(self):
        self.seen: Set[User] = set()

    def add(self, user: User) -> None:
        self._add(user)
        self.seen.add(user)

    def add_all(self, users: Iterable[User]) -> None:
        self._add_all(users)
        for user in users:
            self.seen.add(user)

    def get(self, user_id: str) -> Optional[User]:
        user = self._get(user_id)
        if user:
            self.seen.add(user)
        return user

    @abc.abstractmethod
    def _add(self, user: User) -> None:
        raise NotImplementedError

    def _add_all(self, users: Iterable[User]) -> None:
        for user in users:
            self._add(user)

    @abc.abstractmethod
    def _get(self, user_id: str) -> Optional[User]:
        raise NotImplementedError

class InMemoryUserRepository(AbstractUserRepository):
    def __init__(self, users_dict: Optional[Dict[str, User]] = None):
        super().__init__()
        self._users: Dict[str, User] = users_dict if users_dict is not None else {}

    def _add(self, user: User) -> None:
        self._users[user.user_id] = user

    def _add_all(self, users: Iterable[User]) -> None:
        for user in users:
            self._users[user.user_id] = user

    def _get(self, user_id: str) -> Optional[User]:
        return self._users.get(user_id)


class SqlModelUserRepository(AbstractUserRepository):
    def __init__(self, session: Session):
        super().__init__()
        self.session = session

    def _add(self, user: User) -> None:
        db_user = self.session.get(UserModel, user.user_id)
        if not db_user:
            db_user = UserModel(
                user_id=user.user_id,
                password_hash=user.password_hash,
                secret_key=user.secret_key,
                counter=user.counter,
            )
            self.session.add(db_user)
        else:
            db_user.password_hash = user.password_hash
            db_user.secret_key = user.secret_key
            db_user.counter = user.counter
            self.session.add(db_user)

    def _add_all(self, users: Iterable[User]) -> None:
        user_list = list(users)
        if not user_list:
            return

        chunk_size = 500
        for i in range(0, len(user_list), chunk_size):
            chunk = user_list[i : i + chunk_size]
            user_ids = [u.user_id for u in chunk]
            statement = select(UserModel).where(UserModel.user_id.in_(user_ids))
            existing_map = {
                db_u.user_id: db_u
                for db_u in self.session.exec(statement).all()
            }

            for user in chunk:
                db_user = existing_map.get(user.user_id)
                if not db_user:
                    db_user = UserModel(
                        user_id=user.user_id,
                        password_hash=user.password_hash,
                        secret_key=user.secret_key,
                        counter=user.counter,
                    )
                    self.session.add(db_user)
                else:
                    db_user.password_hash = user.password_hash
                    db_user.secret_key = user.secret_key
                    db_user.counter = user.counter
                    self.session.add(db_user)

    def _get(self, user_id: str) -> Optional[User]:
        db_user = self.session.get(UserModel, user_id)
        if not db_user:
            return None
        user = User(
            user_id=db_user.user_id,
            password_hash=db_user.password_hash,
            secret_key=db_user.secret_key,
            counter=db_user.counter,
        )
        return user
