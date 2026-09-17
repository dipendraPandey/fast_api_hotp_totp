"""Message Bus for executing commands and handling events."""
import logging
from typing import Any, Callable, Dict, List, Type, Union
from app.domain import commands, events
from app.service_layer import handlers
from app.service_layer.unit_of_work import AbstractUnitOfWork

logger = logging.getLogger(__name__)

Message = Union[commands.Command, events.Event]

class MessageBus:
    def __init__(
        self,
        uow: AbstractUnitOfWork,
        event_handlers: Dict[Type[events.Event], List[Callable]] = None,
        command_handlers: Dict[Type[commands.Command], Callable] = None,
    ):
        self.uow = uow
        self.event_handlers = (
            event_handlers if event_handlers is not None else handlers.EVENT_HANDLERS
        )
        self.command_handlers = (
            command_handlers if command_handlers is not None else handlers.COMMAND_HANDLERS
        )

    def handle(self, message: Message) -> Any:
        self.queue = [message]
        results = []
        while self.queue:
            msg = self.queue.pop(0)
            if isinstance(msg, events.Event):
                self._handle_event(msg)
            elif isinstance(msg, commands.Command):
                cmd_result = self._handle_command(msg)
                results.append(cmd_result)
            else:
                raise Exception(f"{msg} was not an Event or Command")
        return results[0] if results else None

    def _handle_event(self, event: events.Event):
        for handler in self.event_handlers.get(type(event), []):
            try:
                logger.debug(f"Handling event {event} with handler {handler}")
                handler(event)
            except Exception:
                logger.exception(f"Exception handling event {event}")

    def _handle_command(self, command: commands.Command) -> Any:
        logger.debug(f"Handling command {command}")
        handler = self.command_handlers.get(type(command))
        if not handler:
            raise Exception(f"No handler for {type(command)}")
        try:
            result = handler(command, uow=self.uow)
            self.queue.extend(self.uow.collect_new_events())
            return result
        except Exception:
            logger.exception(f"Exception handling command {command}")
            raise
