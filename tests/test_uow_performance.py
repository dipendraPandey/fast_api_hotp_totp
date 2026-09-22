import time
import pytest
from sqlalchemy import event
from sqlmodel import SQLModel, Session, create_engine
from app.adapters.repository import UserModel
from app.domain.models import User
from app.service_layer.unit_of_work import SqlModelUnitOfWork


def create_test_engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return engine


def test_uow_commit_query_count_and_correctness():
    engine = create_test_engine()
    session_factory = lambda: Session(engine)

    query_count = 0

    def count_queries(conn, cursor, statement, parameters, context, executemany):
        nonlocal query_count
        query_count += 1

    event.listen(engine, "before_cursor_execute", count_queries)

    # 1. Register N users in UoW
    N = 100
    uow = SqlModelUnitOfWork(session_factory=session_factory)
    with uow:
        for i in range(N):
            user = User(
                user_id=f"user_{i}",
                password_hash="hash",
                secret_key=b"secret",
                counter=0.0
            )
            uow.users.add(user)

        query_count = 0
        start_time = time.perf_counter()
        uow.commit()
        commit_time = time.perf_counter() - start_time
        print(f"\n[BENCHMARK] Commit {N} users: query_count={query_count}, time={commit_time:.4f}s")

    # Verify users are stored in DB
    with session_factory() as session:
        db_users = session.query(UserModel).all()
        assert len(db_users) == N

    # 2. Update N users in UoW
    uow2 = SqlModelUnitOfWork(session_factory=session_factory)
    with uow2:
        for i in range(N):
            user = uow2.users.get(f"user_{i}")
            user.counter += 1.0

        query_count = 0
        start_time = time.perf_counter()
        uow2.commit()
        commit_time = time.perf_counter() - start_time
        print(f"[BENCHMARK] Update {N} users commit: query_count={query_count}, time={commit_time:.4f}s")

    # Verify updates in DB
    with session_factory() as session:
        for i in range(N):
            db_user = session.get(UserModel, f"user_{i}")
            assert db_user.counter == 1.0

    event.remove(engine, "before_cursor_execute", count_queries)
