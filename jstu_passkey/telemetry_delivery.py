from __future__ import annotations

import queue
import threading
import time
from importlib import import_module

from .storage import TelemetrySettings

_QUEUE_LIMIT = 128


class AsyncTelemetryDelivery:
    """Bounded best-effort sender, created only for server-relayed external telemetry."""

    def __init__(self, settings: TelemetrySettings):
        self._sender = _sender_for(settings)
        self._queue: queue.Queue[dict | None] = queue.Queue(maxsize=_QUEUE_LIMIT)
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._sent = 0
        self._failed = 0
        self._dropped = 0
        self._last_error = ""
        self._last_attempt_at: int | None = None
        self._last_success_at: int | None = None
        self._worker = threading.Thread(
            target=self._run,
            name=f"passkey-telemetry-{settings.backend}",
            daemon=True,
        )
        self._worker.start()

    def enqueue(self, event: dict) -> bool:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._lock:
                self._dropped += 1
            return False
        return True

    def status(self) -> dict:
        with self._lock:
            return {
                "state": "running" if not self._stopping.is_set() else "stopping",
                "queued": self._queue.qsize(),
                "sent": self._sent,
                "failed": self._failed,
                "dropped": self._dropped,
                "lastError": self._last_error,
                "lastAttemptAt": self._last_attempt_at,
                "lastSuccessAt": self._last_success_at,
            }

    def stop(self) -> None:
        self._stopping.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass

    def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                event = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if event is None:
                return
            now = int(time.time())
            with self._lock:
                self._last_attempt_at = now
            try:
                self._sender.send(event)
            except Exception as error:
                with self._lock:
                    self._failed += 1
                    self._last_error = _safe_error(error)
            else:
                with self._lock:
                    self._sent += 1
                    self._last_error = ""
                    self._last_success_at = int(time.time())
            finally:
                self._queue.task_done()


def test_backend(settings: TelemetrySettings) -> dict:
    sender = _sender_for(settings)
    started = time.perf_counter()
    sender.test()
    return {
        "ok": True,
        "backend": settings.backend,
        "latencyMs": round((time.perf_counter() - started) * 1000, 1),
    }


def create_direct_target(settings: TelemetrySettings, metadata: dict) -> dict:
    sender = _sender_for(settings)
    return sender.create_direct_target(metadata)


def _sender_for(settings: TelemetrySettings):
    if settings.backend not in {"jason", "custom"}:
        raise ValueError("外部遥测发送器不可用")
    modules = {
        "jason": (
            "jstu_passkey.telemetry_backends."
            "jason_telemetry_integrate"
        ),
        "custom": (
            "jstu_passkey.telemetry_backends."
            "custom_telemetry_integrate"
        ),
    }
    module = import_module(modules[settings.backend])
    return module.Sender(settings)


def _safe_error(error: Exception) -> str:
    name = type(error).__name__
    message = str(error).strip()
    if message.startswith("telemetry_"):
        return message[:120]
    return name[:120]
