---
name: ctrace
description: Live OS-level tracing with dtrace (macOS) or bpftrace (Linux) — no recompilation needed. Use when a user wants to investigate latency spikes or tail latency, trace syscalls, find memory allocation hotspots, diagnose I/O bottlenecks, measure scheduling jitter, or analyze a real-time loop (robotics, game engines, audio, HFT). Trigger on phrases like "what's slow", "tail latency", "syscall overhead", "jitter", "OS-level issues", "memory pressure", "bottleneck in production", "off-CPU".
user-invocable: false
---

# ctrace — Live Process Tracing

ctrace is an MCP server that wraps dtrace (macOS) and bpftrace (Linux) for non-intrusive live tracing of running processes.

## Workflow

### Initial Diagnosis
1. Attach to a process: `ctrace_attach(pid=<PID>)` or launch one: `ctrace_launch(command=["./binary"])`
2. Quick overview: `ctrace_snapshot()` — 1-second capture of syscalls, allocations, scheduling

### Drill Down Based on Snapshot
- **Syscall-heavy**: `ctrace_syscall_summary()` then `ctrace_syscall_trace(syscalls=["read"], min_latency_us=100)`
- **Allocation-heavy**: `ctrace_alloc_summary()` then `ctrace_alloc_hotspots()`
- **I/O-heavy**: `ctrace_io_summary()` then `ctrace_io_latency(threshold_us=1000)`
- **Scheduling issues**: `ctrace_sched_summary()`, `ctrace_lock_contention()`, `ctrace_offcpu()`

### Tick/Frame Analysis (real-time loops)
1. Find the mangled symbol: `nm <binary> | grep <function_name>` (C++ names are mangled on Linux)
2. Define the loop: `ctrace_define_tick(name="physics", function="<mangled_name>")`
3. Measure: `ctrace_tick_summary(tick_name="physics", duration=30)`
4. Find outliers: `ctrace_tick_outliers(tick_name="physics", threshold_us=1000)`
5. Compare fast vs slow: `ctrace_tick_compare(tick_name="physics")`

### Custom Tracing
- `ctrace_probe(script="...")` — run any dtrace/bpftrace script with `$target` as PID placeholder. Use this to correlate syscalls with specific ticks or build any analysis not covered by the other tools.

### Session Management
- `ctrace_sessions()` — list all active sessions
- `ctrace_kill_session(session_id="s1")` — remove a session (does NOT kill the process)
- `ctrace_list_ticks()` — list defined tick loops

## Tips
- Default trace duration is 5 seconds. Use 1-2s for quick checks, 10-30s for rare events.
- Tick analysis requires the binary to have symbols (compile with `-g`).
- All tools accept optional `session_id` — only needed with multiple sessions.
- For short-lived processes, use `ctrace_launch` and start tracing immediately.
- `ctrace_syscall_trace(min_latency_us=0)` captures every syscall, not just slow ones.
- `tick_outliers` identifies which ticks exceeded the threshold but does not capture what happened inside them. For per-outlier syscall/alloc detail, use `ctrace_probe` with a script bracketed by uprobe entry/exit, filtering on tick duration.
