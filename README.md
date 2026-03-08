# ctrace

AI-friendly live tracing MCP server. Wraps dtrace (macOS) and bpftrace (Linux) to non-intrusively observe running processes — measuring syscall latencies, memory allocation patterns, I/O behavior, scheduling delays, and correlating them to real-time loop iterations.

Primary use case: diagnosing tail latency, memory pressure, I/O bottlenecks, and concurrency pathologies in 1000hz+ real-time loops (robotics, game engines, audio).

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/slocook/ctrace/main/install.sh | bash
```

Or from a local checkout:

```bash
./install.sh
```

This will:
1. Clone the repo to `~/.local/share/ctrace` (or use existing checkout)
2. Install Python dependencies via `uv`
3. Set up passwordless sudo for dtrace/bpftrace (prompts for approval)
4. Register ctrace as an MCP server in Claude Code
5. Install the skill to `~/.claude/skills/ctrace/`

Set `CTRACE_HOME` to customize the install location.

### Manual setup

```bash
git clone https://github.com/slocook/ctrace.git ~/.local/share/ctrace
cd ~/.local/share/ctrace && uv sync
claude mcp add --scope user ctrace -- uv run --directory ~/.local/share/ctrace ctrace-mcp
```

## Tools (21)

### Session Management
| Tool | Description |
|------|-------------|
| `ctrace_attach` | Attach to a running process by PID |
| `ctrace_launch` | Launch a binary and create a session |
| `ctrace_sessions` | List active sessions |
| `ctrace_kill_session` | Destroy session (does NOT kill process) |
| `ctrace_status` | Process status: alive, CPU%, memory, threads, FDs |

### Syscall Analysis
| Tool | Description |
|------|-------------|
| `ctrace_syscall_summary` | Top syscalls by count and latency (profile fallback with SIP) |
| `ctrace_syscall_trace` | Trace individual slow syscalls with args and return values |

### Memory Analysis
| Tool | Description |
|------|-------------|
| `ctrace_alloc_summary` | malloc/free rates, size distribution (magmalloc fallback with SIP) |
| `ctrace_alloc_hotspots` | Top allocation call sites by count and bytes |

### I/O Analysis
| Tool | Description |
|------|-------------|
| `ctrace_io_summary` | Read/write ops by FD, bytes, latency |
| `ctrace_io_latency` | I/O operations exceeding latency threshold |

### Scheduling & Concurrency
| Tool | Description |
|------|-------------|
| `ctrace_sched_summary` | Per-thread on/off CPU time, context switches |
| `ctrace_lock_contention` | Mutex waits exceeding threshold |
| `ctrace_offcpu` | Off-CPU stack traces |

### Tick/Frame Analysis
| Tool | Description |
|------|-------------|
| `ctrace_define_tick` | Define a recurring loop by entry function name |
| `ctrace_tick_summary` | Per-tick: min/median/p99/max duration, syscalls, allocs |
| `ctrace_tick_outliers` | Ticks exceeding deadline with root cause breakdown |
| `ctrace_tick_compare` | Compare fast (p50) vs slow (p99+) ticks |
| `ctrace_list_ticks` | List defined tick loops |

### General
| Tool | Description |
|------|-------------|
| `ctrace_probe` | Run custom dtrace/bpftrace scripts (`$target` = PID) |
| `ctrace_snapshot` | Quick 1-second overview of everything |

## Platform Support

### macOS with SIP enabled (default)

Most Macs have System Integrity Protection enabled, which blocks `syscall`, `pid`, and `sched` dtrace probes. ctrace falls back to `fs_usage` (per-syscall tracing) and `profile` sampling:

| Feature | SIP On | SIP Off |
|---------|--------|---------|
| Attach/status/sessions | Full | Full |
| Syscall summary & trace | `fs_usage` (per-call, with latency) | dtrace `syscall:::` probes |
| I/O summary & latency | `fs_usage -f filesys` | dtrace `syscall::read/write` |
| CPU profiling (snapshot, probe) | dtrace `profile-N` sampling | Full |
| Memory regions (alloc_summary) | dtrace `magmalloc` provider | dtrace `pid` provider (per-malloc) |
| Scheduling analysis | Blocked | Full |
| Tick analysis | Blocked | Full |
| Custom probes | profile/tick/magmalloc | All providers |

To disable SIP: boot into Recovery Mode, run `csrutil disable`. Re-enable with `csrutil enable`.

### macOS with SIP disabled

All 21 tools fully functional.

### Linux with bpftrace

All 21 tools fully functional. No SIP equivalent — bpftrace just needs root (or `CAP_BPF`).

```bash
sudo apt install bpftrace  # Ubuntu/Debian
sudo dnf install bpftrace  # Fedora
```

## Architecture

```
Claude Code (MCP client)
    ↓ MCP protocol (stdio)
mcp_server.py (FastMCP)
    ↓ generates scripts, parses output
dtrace_backend.py (macOS)  /  bpftrace_backend.py (Linux)
    ↓ subprocess
sudo dtrace / sudo bpftrace
    ↓ probes
Target process (uninstrumented, keeps running)
```

## Development

```bash
uv sync
uv run pytest tests/ -v
```

### Test target

A C++ program that simulates a 100Hz control loop with allocations, I/O, and latency spikes:

```bash
clang++ -std=c++11 -O1 -g -o test_target tests/test_target.cpp
./test_target &
# Then use ctrace tools to trace it
```
