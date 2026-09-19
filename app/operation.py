"""Request-scoped work, bounded progress delivery, and cooperative cancellation."""

import asyncio
from contextvars import ContextVar
import json
from queue import Empty, Full, Queue
from threading import Event, Thread
from time import monotonic

from fastapi.responses import StreamingResponse


class OperationStopped(Exception):
    pass


_current = ContextVar("operation", default=None)


def checkpoint():
    operation = _current.get()
    if operation:
        if operation.cancelled.is_set():
            raise OperationStopped("Operation cancelled.")
        if monotonic() >= operation.deadline:
            raise OperationStopped("Operation time limit reached. Download any partial report already received.")


class Operation:
    def __init__(self, work, lock, timeout=7200):
        self.cancelled = Event()
        self.done = Event()
        self.deadline = monotonic() + timeout
        self.events = Queue(maxsize=2)
        self.thread = Thread(target=self._run, args=(work, lock), daemon=True)

    def emit(self, kind, data):
        while True:
            checkpoint()
            try:
                self.events.put({"type": kind, "data": data}, timeout=0.25)
                return
            except Full:
                continue

    def _run(self, work, lock):
        from app.chat import ChatError
        from app.fetcher import FetchError

        context = _current.set(self)
        try:
            checkpoint()
            result = work(self.emit)
            self.emit("complete", result)
        except Exception as exc:
            # Only service errors already sanitized upstream can reach the browser.
            detail = str(exc) if isinstance(exc, (ChatError, FetchError, OperationStopped)) else "Operation failed. Please try again."
            status = 400 if isinstance(exc, FetchError) else 502
            if not self.cancelled.is_set():
                try:
                    self.events.put({"type": "error", "data": {"detail": detail, "status": status}}, timeout=0.25)
                except Full:
                    pass
        finally:
            _current.reset(context)
            lock.release()
            self.done.set()

    async def events_async(self):
        heartbeat = monotonic()
        try:
            while True:
                try:
                    event = await asyncio.to_thread(self.events.get, True, 0.5)
                except Empty:
                    if self.done.is_set():
                        return
                    if monotonic() - heartbeat >= 15:
                        heartbeat = monotonic()
                        yield {"type": "heartbeat", "data": {}}
                    continue
                yield event
                if event["type"] in {"complete", "error"}:
                    return
        finally:
            # Keep the slot occupied until the in-flight provider call finishes.
            self.cancelled.set()

    def response(self):
        async def lines():
            try:
                async for event in self.events_async():
                    yield json.dumps(event, ensure_ascii=False) + "\n"
            finally:
                self.cancelled.set()

        return StreamingResponse(lines(), media_type="application/x-ndjson",
                                 headers={"X-Accel-Buffering": "no"})
