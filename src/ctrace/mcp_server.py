"""MCP server exposing ctrace tools via FastMCP."""

from __future__ import annotations

from fastmcp import FastMCP

from ctrace.backend import Backend, get_backend

mcp = FastMCP("ctrace")
_backend: Backend | None = None


def _get_backend() -> Backend:
    global _backend
    if _backend is None:
        _backend = get_backend()
    return _backend


# --- Binary & Process Inspection ---


@mcp.tool()
async def ctrace_symbols(
    filter: str | None = None,
    session_id: str | None = None,
) -> dict:
    """List probeable function symbols from the session binary.

    Returns all text symbols with mangled names (use with ctrace_define_tick),
    demangled names (human-readable), and tick_candidate flags for functions
    that look like good loop targets. Use filter to narrow results by name.

    Args:
        filter: Optional substring to filter results (matches mangled or demangled name)
        session_id: Session to inspect (optional if only one session exists)
    """
    return _get_backend().symbols(session_id, filter)


@mcp.tool()
async def ctrace_threads(session_id: str | None = None) -> dict:
    """List all threads of the traced process with names and CPU times.

    Thread names come from pthread_setname_np and can be passed directly
    to ctrace_define_tick as thread_filter to scope tick analysis to a
    specific thread.

    Args:
        session_id: Session to inspect (optional if only one session exists)
    """
    return _get_backend().threads(session_id)


# --- Session Management ---


@mcp.tool()
async def ctrace_attach(pid: int) -> dict:
    """Attach to a running process by PID. Creates a tracing session.
    Validates the PID exists and returns process info."""
    return await _get_backend().attach(pid)


@mcp.tool()
async def ctrace_launch(command: list[str]) -> dict:
    """Launch a binary with optional args and create a tracing session.
    Returns the session ID and PID of the launched process.

    Args:
        command: Command and arguments, e.g. ["./my_binary", "--flag"]
    """
    return await _get_backend().launch(command)


@mcp.tool()
async def ctrace_sessions() -> list[dict]:
    """List all active tracing sessions with their PIDs and status."""
    return _get_backend().sessions.list_all()


@mcp.tool()
async def ctrace_kill_session(session_id: str) -> dict:
    """Destroy a tracing session. Does NOT kill the target process.

    Args:
        session_id: Session to remove (e.g. "s1")
    """
    return await _get_backend().kill_session(session_id)


@mcp.tool()
async def ctrace_status(session_id: str | None = None) -> dict:
    """Get process status: alive, CPU%, memory, thread count, open FDs.

    Args:
        session_id: Session to query (optional if only one session exists)
    """
    return await _get_backend().status(session_id)


# --- Syscall Analysis ---


@mcp.tool()
async def ctrace_syscall_summary(
    duration: float = 5.0,
    top_n: int = 20,
    session_id: str | None = None,
) -> dict:
    """Top syscalls by count and cumulative latency. Shows histogram of latencies per syscall.

    Args:
        duration: How long to trace in seconds (default 5)
        top_n: Number of top syscalls to return (default 20)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().syscall_summary(session_id, duration, top_n)


@mcp.tool()
async def ctrace_syscall_trace(
    duration: float = 5.0,
    syscalls: list[str] | None = None,
    min_latency_us: int = 100,
    session_id: str | None = None,
) -> dict:
    """Trace specific syscalls (or all slow ones). Returns individual events with args, return value, latency.

    Args:
        duration: How long to trace in seconds (default 5)
        syscalls: List of syscall names to trace (e.g. ["read", "write"]). All if None.
        min_latency_us: Only capture syscalls slower than this (microseconds, default 100)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().syscall_trace(session_id, duration, syscalls, min_latency_us)


# --- Memory Analysis ---


@mcp.tool()
async def ctrace_alloc_summary(
    duration: float = 5.0,
    session_id: str | None = None,
) -> dict:
    """malloc/free/realloc rates, size distribution, net allocation rate (pressure indicator).

    Args:
        duration: How long to trace in seconds (default 5)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().alloc_summary(session_id, duration)


@mcp.tool()
async def ctrace_alloc_hotspots(
    duration: float = 5.0,
    top_n: int = 10,
    session_id: str | None = None,
) -> dict:
    """Top allocation call sites by count and total bytes. Requires binary with symbols.

    Args:
        duration: How long to trace in seconds (default 5)
        top_n: Number of top call sites to return (default 10)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().alloc_hotspots(session_id, duration, top_n)


# --- I/O Analysis ---


@mcp.tool()
async def ctrace_io_summary(
    duration: float = 5.0,
    session_id: str | None = None,
) -> dict:
    """Read/write ops by file descriptor, bytes transferred, latency. Identifies I/O-heavy FDs.

    Args:
        duration: How long to trace in seconds (default 5)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().io_summary(session_id, duration)


@mcp.tool()
async def ctrace_io_latency(
    duration: float = 5.0,
    threshold_us: int = 1000,
    session_id: str | None = None,
) -> dict:
    """I/O operations exceeding latency threshold. Shows which files/sockets are slow.

    Args:
        duration: How long to trace in seconds (default 5)
        threshold_us: Latency threshold in microseconds (default 1000)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().io_latency(session_id, duration, threshold_us)


# --- Scheduling & Concurrency ---


@mcp.tool()
async def ctrace_sched_summary(
    duration: float = 5.0,
    session_id: str | None = None,
) -> dict:
    """Per-thread: on-cpu time, off-cpu time, context switches, wakeup latency.

    Args:
        duration: How long to trace in seconds (default 5)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().sched_summary(session_id, duration)


@mcp.tool()
async def ctrace_lock_contention(
    duration: float = 5.0,
    threshold_us: int = 100,
    session_id: str | None = None,
) -> dict:
    """Mutex/futex waits exceeding threshold. Shows which locks cause contention.

    Args:
        duration: How long to trace in seconds (default 5)
        threshold_us: Minimum wait time in microseconds (default 100)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().lock_contention(session_id, duration, threshold_us)


@mcp.tool()
async def ctrace_offcpu(
    duration: float = 5.0,
    min_us: int = 100,
    session_id: str | None = None,
) -> dict:
    """Off-CPU flame-graph data: why threads are sleeping and for how long.

    Args:
        duration: How long to trace in seconds (default 5)
        min_us: Minimum off-cpu time in microseconds to capture (default 100)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().offcpu(session_id, duration, min_us)


# --- Tick/Frame Analysis ---


@mcp.tool()
async def ctrace_define_tick(
    name: str,
    function: str,
    thread_filter: str | None = None,
    session_id: str | None = None,
) -> dict:
    """Define a recurring loop by its entry function (e.g., physics_update, control_loop).
    Multiple independent loops can be defined. Used by tick analysis tools.

    Args:
        name: Name for this tick (e.g. "physics", "render")
        function: Entry function name (e.g. "physics_update")
        thread_filter: Optional thread name filter
        session_id: Session to configure (optional if only one session exists)
    """
    return _get_backend().define_tick(session_id, name, function, thread_filter)


@mcp.tool()
async def ctrace_tick_summary(
    tick_name: str,
    duration: float = 5.0,
    session_id: str | None = None,
) -> dict:
    """Per-tick stats: min/median/p99/max duration, syscall count, alloc count, off-cpu time.

    Args:
        tick_name: Name of a defined tick (from ctrace_define_tick)
        duration: How long to trace in seconds (default 5)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().tick_summary(session_id, tick_name, duration)


@mcp.tool()
async def ctrace_tick_outliers(
    tick_name: str,
    duration: float = 5.0,
    threshold_us: int = 1000,
    session_id: str | None = None,
) -> dict:
    """Ticks exceeding deadline. For each outlier: what happened (syscalls, allocs, scheduling delays).

    Args:
        tick_name: Name of a defined tick
        duration: How long to trace in seconds (default 5)
        threshold_us: Deadline in microseconds — ticks slower than this are outliers (default 1000)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().tick_outliers(session_id, tick_name, duration, threshold_us)


@mcp.tool()
async def ctrace_tick_compare(
    tick_name: str,
    duration: float = 5.0,
    session_id: str | None = None,
) -> dict:
    """Compare fast ticks (p50) vs slow ticks (p99+). Shows what differs: extra syscalls, allocations, lock waits.

    Args:
        tick_name: Name of a defined tick
        duration: How long to trace in seconds (default 5)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().tick_compare(session_id, tick_name, duration)


@mcp.tool()
async def ctrace_list_ticks(session_id: str | None = None) -> list[dict]:
    """List defined tick loops with their functions.

    Args:
        session_id: Session to query (optional if only one session exists)
    """
    return _get_backend().list_ticks(session_id)


# --- General ---


@mcp.tool()
async def ctrace_probe(
    script: str,
    duration: float = 5.0,
    session_id: str | None = None,
) -> dict:
    """Run a custom dtrace/bpftrace script. Use $target as PID placeholder.
    Returns raw output. Escape hatch for anything not covered by other tools.

    Args:
        script: dtrace/bpftrace script text. Use $target for the session PID.
        duration: How long to run in seconds (default 5)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().probe(session_id, script, duration)


@mcp.tool()
async def ctrace_snapshot(
    duration: float = 1.0,
    session_id: str | None = None,
) -> dict:
    """Quick capture of: syscall mix, alloc rate, sched delays, tick stats (if defined).
    One-shot overview for initial diagnosis.

    Args:
        duration: How long to capture in seconds (default 1)
        session_id: Session to trace (optional if only one session exists)
    """
    return await _get_backend().snapshot(session_id, duration)


def main():
    mcp.run()
