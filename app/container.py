"""Dependency Injection Container using PyPI 'di'."""
import di
from di.dependent import Dependent
from di.executors import AsyncExecutor

from app.service_layer.unit_of_work import AbstractUnitOfWork, SqlModelUnitOfWork
from app.service_layer.messagebus import MessageBus

container = di.Container()

def get_uow() -> AbstractUnitOfWork:
    return SqlModelUnitOfWork()

def get_message_bus(uow: AbstractUnitOfWork = None) -> MessageBus:
    if uow is None:
        uow = get_uow()
    return MessageBus(uow=uow)

# Bind abstract UoW to concrete SqlModelUnitOfWork for container DI resolution
container.bind(
    di.bind_by_type(Dependent(SqlModelUnitOfWork, scope="request"), AbstractUnitOfWork)
)

executor = AsyncExecutor()

async def resolve_message_bus() -> MessageBus:
    """Helper to resolve MessageBus instance using di container."""
    solved = container.solve(Dependent(get_message_bus, scope="request"), scopes=["request"])
    async with container.enter_scope("request") as state:
        bus = await solved.execute_async(executor=executor, state=state)
        return bus
