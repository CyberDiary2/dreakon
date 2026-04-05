"""
Event bus for inter-phase communication.
Phases emit events; the orchestrator subscribes and triggers downstream work.
"""
import asyncio
from dataclasses import dataclass, field
from enum import Enum


class EventType(str, Enum):
    NEW_SUBDOMAIN = "new_subdomain"
    NEW_ENDPOINT = "new_endpoint"
    NEW_JS_FILE = "new_js_file"
    NEW_FINDING = "new_finding"
    CERT_SANS = "cert_sans"
    PHASE_COMPLETE = "phase_complete"


@dataclass
class Event:
    type: EventType
    data: dict = field(default_factory=dict)


class EventBus:
    def __init__(self):
        self._queue: asyncio.Queue[Event] = asyncio.Queue()

    async def emit(self, event_type: EventType, **data):
        await self._queue.put(Event(type=event_type, data=data))

    async def get(self) -> Event:
        return await self._queue.get()

    def task_done(self):
        self._queue.task_done()

    def empty(self) -> bool:
        return self._queue.empty()

    async def join(self):
        await self._queue.join()


bus = EventBus()
