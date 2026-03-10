"""Abstract backend, Session management, and script runner helpers."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import re
import signal
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Thread names in practice are simple identifiers. Restrict to safe characters
# so values cannot break bpftrace (`comm == "..."`) or dtrace predicate syntax.
_THREAD_FILTER_RE = re.compile(r'^[A-Za-z0-9_.\ -]{1,64}$')

from ctrace.schema import Capabilities, TraceEvent, build_envelope

import psutil

SCRIPTS_DIR = Path(__file__).parent / "scripts"


@dataclass
class TickDefinition:
    name: str
    function: str
    thread_filter: str | None = None


@dataclass
class Session:
    session_id: str
    pid: int
    binary_path: str | None = None
    ticks: dict[str, TickDefinition] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    _launched: bool = False

    def is_alive(self) -> bool:
        try:
            return psutil.pid_exists(self.pid) and psutil.Process(self.pid).status() != psutil.STATUS_ZOMBIE
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def status_info(self) -> dict[str, Any]:
        try:
            proc = psutil.Process(self.pid)
            with proc.oneshot():
                return {
                    "pid": self.pid,
                    "alive": True,
                    "name": proc.name(),
                    "status": proc.status(),
                    "cpu_percent": proc.cpu_percent(interval=0.1),
                    "memory_rss_mb": round(proc.memory_info().rss / 1048576, 2),
                    "num_threads": proc.num_threads(),
                    "num_fds": proc.num_fds() if hasattr(proc, "num_fds") else None,
                    "create_time": proc.create_time(),
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {"pid": self.pid, "alive": False}


class SessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._counter = 0

    def create(self, pid: int, binary_path: str | None = None, launched: bool = False) -> Session:
        self._counter += 1
        sid = f"s{self._counter}"
        session = Session(session_id=sid, pid=pid, binary_path=binary_path, _launched=launched)
        self._sessions[sid] = session
        return session

    def get(self, session_id: str) -> Session:
        if session_id not in self._sessions:
            raise ValueError(f"No session '{session_id}'. Active: {list(self._sessions.keys())}")
        return self._sessions[session_id]

    def get_default(self, session_id: str | None) -> Session:
        if session_id:
            return self.get(session_id)
        if len(self._sessions) == 1:
            return next(iter(self._sessions.values()))
        if not self._sessions:
            raise ValueError("No active sessions. Use ctrace_attach or ctrace_launch first.")
        raise ValueError(f"Multiple sessions active: {list(self._sessions.keys())}. Specify session_id.")

    def remove(self, session_id: str) -> None:
        if session_id in self._sessions:
            del self._sessions[session_id]

    def list_all(self) -> list[dict[str, Any]]:
        result = []
        for s in self._sessions.values():
            result.append({
                "session_id": s.session_id,
                "pid": s.pid,
                "binary_path": s.binary_path,
                "alive": s.is_alive(),
                "ticks": list(s.ticks.keys()),
                "created_at": s.created_at,
            })
        return result


class Backend(ABC):
    """Abstract tracing backend (dtrace or bpftrace)."""

    def __init__(self) -> None:
        self.sessions = SessionManager()

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Return backend identifier, e.g. 'dtrace' or 'bpftrace'."""

    def _default_capabilities(self) -> Capabilities:
        """Return default capabilities for this backend. Override in subclasses."""
        return Capabilities(
            has_user_stacks=False,
            has_kernel_stacks=False,
            has_args=False,
            has_retval=False,
            has_tid=False,
            timing_source="derived",
        )

    def _wrap(
        self,
        *,
        tool: str,
        session_id: str,
        pid: int,
        duration_s: float,
        events: list[TraceEvent] | None = None,
        aggregates: dict[str, Any] | None = None,
        raw_output: str | None = None,
        warnings: list[str] | None = None,
        errors: list[str] | None = None,
        capabilities: Capabilities | None = None,
    ) -> dict[str, Any]:
        """Build a trace envelope for a tool response."""
        return build_envelope(
            backend=self.backend_name,
            session_id=session_id,
            pid=pid,
            tool=tool,
            duration_s=duration_s,
            capabilities=capabilities or self._default_capabilities(),
            events=events,
            aggregates=aggregates,
            raw_output=raw_output,
            warnings=warnings,
            errors=errors,
        )

    @abstractmethod
    def tracer_cmd(self) -> list[str]:
        """Return the base command, e.g. ['sudo', 'dtrace'] or ['sudo', 'bpftrace']."""

    @abstractmethod
    def script_ext(self) -> str:
        """Script file extension: '.d' or '.bt'."""

    def load_script(self, name: str) -> str:
        path = SCRIPTS_DIR / f"{name}{self.script_ext()}"
        if not path.exists():
            raise FileNotFoundError(f"Script not found: {path}")
        return path.read_text()

    async def run_script(
        self,
        script: str,
        duration: float = 5.0,
        args: list[str] | None = None,
    ) -> str:
        cmd = self.tracer_cmd() + self._script_args(script) + (args or [])
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=duration + 10
                )
            except asyncio.TimeoutError:
                proc.terminate()
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
                    stdout, stderr = await proc.communicate()

            output = stdout.decode("utf-8", errors="replace")
            errors = stderr.decode("utf-8", errors="replace")
            if proc.returncode and proc.returncode != 0 and not output:
                raise RuntimeError(f"Tracer failed (rc={proc.returncode}): {errors}")
            return output
        except FileNotFoundError:
            raise RuntimeError(
                f"Tracer command not found: {self.tracer_cmd()[0]}. "
                "Ensure dtrace/bpftrace is installed and sudo is configured."
            )

    async def run_timed_script(
        self,
        script: str,
        duration: float = 5.0,
        args: list[str] | None = None,
    ) -> str:
        """Run a script that uses a $DURATION placeholder, sending SIGINT after duration."""
        cmd = self.tracer_cmd() + self._script_args(script) + (args or [])
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.sleep(duration)
        proc.send_signal(signal.SIGINT)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
        except asyncio.TimeoutError:
            proc.kill()
            stdout, stderr = await proc.communicate()

        output = stdout.decode("utf-8", errors="replace")
        errors = stderr.decode("utf-8", errors="replace")
        if not output and errors:
            raise RuntimeError(f"Tracer error: {errors}")
        return output

    @abstractmethod
    def _script_args(self, script: str) -> list[str]:
        """Return args to pass an inline script to the tracer."""

    # --- Common tool implementations ---

    async def attach(self, pid: int) -> dict:
        if not psutil.pid_exists(pid):
            raise ValueError(f"PID {pid} does not exist")
        try:
            proc = psutil.Process(pid)
            binary = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            binary = None
        session = self.sessions.create(pid, binary)
        return {
            "session_id": session.session_id,
            "pid": pid,
            "binary": binary,
            "status": session.status_info(),
        }

    async def launch(self, command: list[str]) -> dict:
        proc = subprocess.Popen(command)
        binary = command[0]
        session = self.sessions.create(proc.pid, binary, launched=True)
        return {
            "session_id": session.session_id,
            "pid": proc.pid,
            "binary": binary,
        }

    async def kill_session(self, session_id: str) -> dict:
        session = self.sessions.get(session_id)
        pid = session.pid
        self.sessions.remove(session_id)
        return {"removed": session_id, "pid": pid, "note": "Process was NOT killed"}

    async def status(self, session_id: str | None) -> dict:
        session = self.sessions.get_default(session_id)
        return session.status_info()

    def define_tick(self, session_id: str | None, name: str, function: str, thread_filter: str | None) -> dict:
        if thread_filter is not None and not _THREAD_FILTER_RE.match(thread_filter):
            raise ValueError(
                f"thread_filter {thread_filter!r} contains invalid characters. "
                "Only alphanumeric, underscore, hyphen, period, and space are allowed (max 64 chars)."
            )
        session = self.sessions.get_default(session_id)
        tick = TickDefinition(name=name, function=function, thread_filter=thread_filter)
        session.ticks[name] = tick
        return {"defined": name, "function": function, "session": session.session_id}

    def list_ticks(self, session_id: str | None) -> list[dict]:
        session = self.sessions.get_default(session_id)
        return [
            {"name": t.name, "function": t.function, "thread_filter": t.thread_filter}
            for t in session.ticks.values()
        ]

    # --- Abstract trace methods ---

    @abstractmethod
    async def syscall_summary(self, session_id: str | None, duration: float, top_n: int) -> dict: ...

    @abstractmethod
    async def syscall_trace(self, session_id: str | None, duration: float, syscalls: list[str] | None, min_latency_us: int) -> dict: ...

    @abstractmethod
    async def alloc_summary(self, session_id: str | None, duration: float) -> dict: ...

    @abstractmethod
    async def alloc_hotspots(self, session_id: str | None, duration: float, top_n: int) -> dict: ...

    @abstractmethod
    async def io_summary(self, session_id: str | None, duration: float) -> dict: ...

    @abstractmethod
    async def io_latency(self, session_id: str | None, duration: float, threshold_us: int) -> dict: ...

    @abstractmethod
    async def sched_summary(self, session_id: str | None, duration: float) -> dict: ...

    @abstractmethod
    async def lock_contention(self, session_id: str | None, duration: float, threshold_us: int) -> dict: ...

    @abstractmethod
    async def offcpu(self, session_id: str | None, duration: float, min_us: int) -> dict: ...

    @abstractmethod
    async def tick_summary(self, session_id: str | None, tick_name: str, duration: float) -> dict: ...

    @abstractmethod
    async def tick_outliers(self, session_id: str | None, tick_name: str, duration: float, threshold_us: int) -> dict: ...

    @abstractmethod
    async def tick_compare(self, session_id: str | None, tick_name: str, duration: float) -> dict: ...

    @abstractmethod
    async def probe(self, session_id: str | None, script: str, duration: float) -> dict: ...

    @abstractmethod
    async def snapshot(self, session_id: str | None, duration: float) -> dict: ...


def get_backend() -> Backend:
    """Create the appropriate backend for this platform."""
    override = os.environ.get("CTRACE_BACKEND", "").lower()
    if override == "dtrace":
        from ctrace.dtrace_backend import DTraceBackend
        return DTraceBackend()
    elif override == "bpftrace":
        from ctrace.bpftrace_backend import BpftraceBackend
        return BpftraceBackend()

    system = platform.system()
    if system == "Darwin":
        from ctrace.dtrace_backend import DTraceBackend
        return DTraceBackend()
    elif system == "Linux":
        from ctrace.bpftrace_backend import BpftraceBackend
        return BpftraceBackend()
    else:
        raise RuntimeError(f"Unsupported platform: {system}. ctrace supports macOS (dtrace) and Linux (bpftrace).")
