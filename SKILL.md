---
name: ctrace
description: Live process tracing with dtrace/bpftrace. Use when diagnosing performance issues, tail latency, memory pressure, I/O bottlenecks, or concurrency problems in running processes. Especially useful for real-time loops (robotics, game engines, audio).
user-invocable: false
---

# ctrace — Live Process Tracing

ctrace is an MCP server that wraps dtrace (macOS) and bpftrace (Linux) for non-intrusive live tracing of running processes.

## Workflow

### Initial Diagnosis
1. Attach to a process: `ctrace_attach(pid=<PID>)` or launch one: `ctrace_launch(command=["./binary"])`
2. Check status: `ctrace_status()`
3. Quick overview: `ctrace_snapshot()` — 1-second capture of syscalls, allocations, scheduling

### Drill Down Based on Snapshot
- **Syscall-heavy**: `ctrace_syscall_summary()` then `ctrace_syscall_trace(syscalls=["read"], min_latency_us=100)`
- **Allocation-heavy**: `ctrace_alloc_summary()` then `ctrace_alloc_hotspots()`
- **I/O-heavy**: `ctrace_io_summary()` then `ctrace_io_latency(threshold_us=1000)`
- **Scheduling issues**: `ctrace_sched_summary()`, `ctrace_lock_contention()`, `ctrace_offcpu()`

### Tick/Frame Analysis (real-time loops)
1. Define the loop: `ctrace_define_tick(name="physics", function="physics_update")`
2. Measure: `ctrace_tick_summary(tick_name="physics")`
3. Find outliers: `ctrace_tick_outliers(tick_name="physics", threshold_us=1000)`
4. Compare fast vs slow: `ctrace_tick_compare(tick_name="physics")`

### Custom Tracing
- `ctrace_probe(script="...")` — run any dtrace/bpftrace script with `$target` as PID placeholder

## Tips
- Default trace duration is 5 seconds. Use 1-2s for quick checks, 10-30s for rare events.
- Tick analysis requires the binary to have symbols (compile with `-g`).
- All tools accept optional `session_id` — only needed with multiple sessions.
- Multiple sessions can be active simultaneously for comparing processes.
