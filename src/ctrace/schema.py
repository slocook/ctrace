"""Structured output types and envelope builder for trace tool responses."""

from __future__ import annotations

import platform
import time
from typing import Any, TypedDict


class WindowInfo(TypedDict, total=False):
    duration_s: float
    start_time_unix_ns: int | None
    end_time_unix_ns: int | None


class Capabilities(TypedDict, total=False):
    has_user_stacks: bool
    has_kernel_stacks: bool
    has_args: bool
    has_retval: bool
    has_tid: bool
    timing_source: str  # "event" | "sample" | "derived"


class TraceEvent(TypedDict, total=False):
    ts_ns: int | None
    category: str  # syscall|alloc|io|sched|lock|offcpu|tick|probe
    name: str
    phase: str  # always "complete" in v1.0
    tid: int | None
    duration_us: int
    status: str  # ok|error|timeout|unknown
    fields: dict[str, Any]
    labels: list[str]


class TraceEnvelope(TypedDict, total=False):
    schema_version: str
    backend: str
    platform: str
    session_id: str
    pid: int
    tool: str
    window: WindowInfo
    capabilities: Capabilities
    events: list[TraceEvent]
    aggregates: dict[str, Any]
    raw_output: str
    warnings: list[str]
    errors: list[str]


def build_envelope(
    *,
    backend: str,
    session_id: str,
    pid: int,
    tool: str,
    duration_s: float,
    capabilities: Capabilities,
    events: list[TraceEvent] | None = None,
    aggregates: dict[str, Any] | None = None,
    raw_output: str | None = None,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Build a trace envelope dict with consistent metadata."""
    end_ns = time.time_ns()
    start_ns = end_ns - int(duration_s * 1_000_000_000)

    envelope: dict[str, Any] = {}

    envelope["schema_version"] = "1.0"
    envelope["backend"] = backend
    envelope["platform"] = "macos" if platform.system() == "Darwin" else "linux"
    envelope["session_id"] = session_id
    envelope["pid"] = pid
    envelope["tool"] = tool
    envelope["window"] = WindowInfo(
        duration_s=duration_s,
        start_time_unix_ns=start_ns,
        end_time_unix_ns=end_ns,
    )
    envelope["capabilities"] = capabilities

    if events is not None:
        envelope["events"] = events
    if aggregates is not None:
        envelope["aggregates"] = aggregates
    if raw_output is not None:
        envelope["raw_output"] = raw_output

    envelope["warnings"] = warnings or []
    envelope["errors"] = errors or []

    return envelope
