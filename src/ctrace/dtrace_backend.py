"""macOS dtrace backend.

Handles both SIP-enabled and SIP-disabled environments.
With SIP on, syscall/pid/sched probes are unavailable — we fall back to
fs_usage (per-syscall tracing), profile sampling, and the magmalloc provider.
"""

from __future__ import annotations

import asyncio
import re
import signal
import subprocess
from collections import defaultdict
from typing import Any

from ctrace.backend import Backend

SIP_MSG = (
    "This tool requires dtrace probes blocked by System Integrity Protection (SIP). "
    "Options: (1) disable SIP (csrutil disable from Recovery Mode), or "
    "(2) use Linux with bpftrace."
)


def _check_sip() -> bool:
    """Return True if SIP is enabled (restricts dtrace)."""
    try:
        result = subprocess.run(
            ["csrutil", "status"], capture_output=True, text=True, timeout=5
        )
        return "enabled" in result.stdout.lower()
    except Exception:
        return True  # assume enabled if we can't check


class DTraceBackend(Backend):

    def __init__(self) -> None:
        super().__init__()
        self._sip_enabled: bool | None = None

    @property
    def sip_enabled(self) -> bool:
        if self._sip_enabled is None:
            self._sip_enabled = _check_sip()
        return self._sip_enabled

    def tracer_cmd(self) -> list[str]:
        return ["sudo", "dtrace"]

    def script_ext(self) -> str:
        return ".d"

    def _script_args(self, script: str) -> list[str]:
        return ["-n", script] if "\n" not in script else ["-s", "/dev/stdin"]

    async def _run_inline(self, script: str, duration: float) -> str:
        """Run a multi-line D script via stdin."""
        cmd = ["sudo", "dtrace", "-q", "-s", "/dev/stdin"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        proc.stdin.write(script.encode())
        proc.stdin.close()
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration + 10)
        except asyncio.TimeoutError:
            try:
                proc.send_signal(signal.SIGINT)
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            except (ProcessLookupError, asyncio.TimeoutError):
                proc.kill()
                stdout, stderr = await proc.communicate()
        output = stdout.decode("utf-8", errors="replace")
        errors = stderr.decode("utf-8", errors="replace")
        if proc.returncode and proc.returncode != 0 and not output:
            if "System Integrity Protection" in errors:
                raise RuntimeError(SIP_MSG)
            raise RuntimeError(f"dtrace failed (rc={proc.returncode}): {errors}")
        return output

    def _sip_error(self, tool_name: str) -> dict:
        return {"error": f"{tool_name}: {SIP_MSG}", "sip_enabled": True}

    async def _run_fs_usage(self, pid: int, duration: float, filter_mode: str | None = None) -> str:
        """Run fs_usage for duration seconds, filtered to a specific PID.
        Works with SIP enabled. Returns raw output.
        filter_mode: None (all), 'filesys', 'network', 'exec', 'cachehit'
        """
        cmd = ["sudo", "fs_usage", "-w", "-t", str(int(duration))]
        if filter_mode:
            cmd.extend(["-f", filter_mode])
        cmd.append(str(pid))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration + 10)
        except asyncio.TimeoutError:
            proc.terminate()
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                stdout, stderr = await proc.communicate()
        return stdout.decode("utf-8", errors="replace")

    def _parse_fs_usage(self, output: str) -> list[dict]:
        """Parse fs_usage -w output into structured events.
        Format: timestamp  syscall  [details]  latency  process.tid
        """
        events = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("THROTTLED") or line.startswith("  "):
                continue
            # Match: timestamp  syscall_name  ... latency_seconds  process.tid
            # The latency is the second-to-last field, process.tid is last
            parts = line.split()
            if len(parts) < 3:
                continue
            timestamp = parts[0]
            syscall = parts[1]
            # Skip WrData/RdData meta lines (indented with spaces, start with spaces)
            if syscall.startswith("WrData") or syscall.startswith("RdData"):
                continue
            # Find latency: it's a float near the end, looks like 0.000035
            # Process.tid is the last field
            proc_tid = parts[-1]
            latency_s = None
            fd = None
            bytes_val = None
            path = None
            for i, p in enumerate(parts[2:], 2):
                if p.startswith("F="):
                    try:
                        fd = int(p[2:])
                    except ValueError:
                        pass
                elif p.startswith("B="):
                    try:
                        bytes_val = int(p[2:], 0)
                    except ValueError:
                        pass
                elif p.startswith("/") and not p.startswith("/dev/NOTFOUND"):
                    path = p
            # Latency is second-to-last field
            try:
                latency_s = float(parts[-2])
            except (ValueError, IndexError):
                pass
            event = {"timestamp": timestamp, "syscall": syscall}
            if fd is not None:
                event["fd"] = fd
            if bytes_val is not None:
                event["bytes"] = bytes_val
            if path:
                event["path"] = path
            if latency_s is not None:
                event["latency_us"] = int(latency_s * 1_000_000)
            events.append(event)
        return events

    def _summarize_fs_usage(self, events: list[dict], top_n: int) -> dict:
        """Summarize fs_usage events into syscall counts and latencies."""
        counts: dict[str, int] = defaultdict(int)
        total_lat: dict[str, int] = defaultdict(int)
        for e in events:
            sc = e["syscall"]
            counts[sc] += 1
            total_lat[sc] += e.get("latency_us", 0)
        sorted_by_count = sorted(counts.items(), key=lambda x: -x[1])[:top_n]
        return {
            "syscalls": [
                {"syscall": sc, "count": counts[sc], "total_latency_us": total_lat[sc]}
                for sc, _ in sorted_by_count
            ],
            "total_events": len(events),
        }

    def _parse_quantize(self, output: str) -> dict[str, list[dict]]:
        """Parse dtrace quantize/lquantize output into structured buckets."""
        result = {}
        current_key = None
        buckets = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                if current_key and buckets:
                    result[current_key] = buckets
                    buckets = []
                continue
            if not line[0].isspace() and "|" not in line and "value" not in line.lower():
                if current_key and buckets:
                    result[current_key] = buckets
                    buckets = []
                current_key = line.strip()
                continue
            m = re.match(r'\s*(\d+)\s*\|.+?\s+(\d+)\s*\|?\s*$', line)
            if m:
                buckets.append({"min": int(m.group(1)), "count": int(m.group(2))})
        if current_key and buckets:
            result[current_key] = buckets
        return result

    def _parse_aggregation(self, output: str) -> list[dict[str, Any]]:
        """Parse dtrace aggregation output like:  key  value"""
        results = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("CPU") or line.startswith("dtrace"):
                continue
            parts = line.rsplit(None, 1)
            if len(parts) == 2:
                try:
                    results.append({"key": parts[0].strip(), "value": int(parts[1])})
                except ValueError:
                    continue
        return results

    def _parse_delimited(self, output: str, fields: list[str], delimiter: str = "|") -> list[dict[str, str]]:
        """Parse pipe-delimited output lines."""
        results = []
        for line in output.splitlines():
            if delimiter not in line:
                continue
            parts = [p.strip() for p in line.split(delimiter)]
            if len(parts) >= len(fields):
                row = {}
                for i, f in enumerate(fields):
                    row[f] = parts[i]
                results.append(row)
        return results

    # ---- Syscall Analysis ----

    async def syscall_summary(self, session_id: str | None, duration: float, top_n: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            # Use fs_usage for per-syscall data (works with SIP)
            output = await self._run_fs_usage(pid, duration)
            events = self._parse_fs_usage(output)
            summary = self._summarize_fs_usage(events, top_n)
            return {
                "pid": pid,
                "duration_s": duration,
                **summary,
            }

        script = f"""
syscall:::entry /pid == {pid}/ {{
    self->ts = timestamp;
    @counts[probefunc] = count();
}}
syscall:::return /pid == {pid} && self->ts/ {{
    this->delta = (timestamp - self->ts) / 1000;
    @latency[probefunc] = sum(this->delta);
    self->ts = 0;
}}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{ exit(0); }}
"""
        output = await self._run_inline(script, duration + 2)
        counts = self._parse_aggregation(output)
        counts.sort(key=lambda x: x["value"], reverse=True)
        return {
            "pid": pid,
            "duration_s": duration,
            "syscalls": counts[:top_n],
            "raw_output": output[:4000],
        }

    async def syscall_trace(self, session_id: str | None, duration: float, syscalls: list[str] | None, min_latency_us: int) -> dict:
        if self.sip_enabled:
            session = self.sessions.get_default(session_id)
            pid = session.pid
            output = await self._run_fs_usage(pid, duration)
            events = self._parse_fs_usage(output)
            # Filter by syscall names and latency threshold
            filtered = []
            for e in events:
                if syscalls and e["syscall"] not in syscalls:
                    continue
                if e.get("latency_us", 0) < min_latency_us:
                    continue
                filtered.append(e)
            return {
                "pid": pid, "duration_s": duration, "min_latency_us": min_latency_us,
                "events": filtered[:500], "total_captured": len(filtered),
            }
        session = self.sessions.get_default(session_id)
        pid = session.pid
        syscall_filter = ""
        if syscalls:
            conds = " || ".join(f'probefunc == "{s}"' for s in syscalls)
            syscall_filter = f" && ({conds})"
        script = f"""
syscall:::entry /pid == {pid}{syscall_filter}/ {{
    self->ts = timestamp; self->arg0 = arg0; self->arg1 = arg1;
}}
syscall:::return /pid == {pid} && self->ts{syscall_filter}/ {{
    this->delta = (timestamp - self->ts) / 1000; self->ts = 0;
}}
syscall:::return /this->delta >= {min_latency_us} && pid == {pid}{syscall_filter}/ {{
    printf("TRACE|%s|%d|%d|%d|%d\\n", probefunc, self->arg0, self->arg1, arg1, this->delta);
}}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{ exit(0); }}
"""
        output = await self._run_inline(script, duration + 2)
        events = self._parse_delimited(output, ["_marker", "syscall", "arg0", "arg1", "retval", "latency_us"])
        cleaned = [
            {k: e[k] for k in ["syscall", "arg0", "arg1", "retval", "latency_us"] if k in e}
            for e in events if e.get("_marker") == "TRACE"
        ]
        return {
            "pid": pid, "duration_s": duration, "min_latency_us": min_latency_us,
            "events": cleaned[:500], "total_captured": len(cleaned),
        }

    # ---- Memory Analysis ----

    async def alloc_summary(self, session_id: str | None, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            # Use magmalloc provider for region-level allocation tracking
            script = f"""
magmalloc{pid}:::allocRegion {{
    @alloc_regions = count();
    @alloc_bytes = sum(arg0);
    @alloc_sizes = quantize(arg0);
}}
magmalloc{pid}:::deallocRegion {{
    @dealloc_regions = count();
}}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{
    printa("alloc_regions %@d\\n", @alloc_regions);
    printa("alloc_bytes %@d\\n", @alloc_bytes);
    printa("dealloc_regions %@d\\n", @dealloc_regions);
    printf("\\n--- SIZE DISTRIBUTION ---\\n");
    printa(@alloc_sizes);
    exit(0);
}}
"""
            output = await self._run_inline(script, duration + 2)
            summary = {}
            for line in output.splitlines():
                for key in ["alloc_regions", "alloc_bytes", "dealloc_regions"]:
                    if key in line:
                        m = re.search(r'(\d+)', line.split(key)[-1])
                        if m:
                            summary[key] = int(m.group(1))
            return {
                "pid": pid, "duration_s": duration,
                "note": "SIP enabled — showing memory region allocations (not individual malloc calls)",
                "summary": summary, "raw_output": output[:4000],
            }

        script = f"""
pid{pid}::malloc:entry {{
    @malloc_count = count(); @malloc_bytes = sum(arg0); @malloc_sizes = quantize(arg0);
}}
pid{pid}::free:entry {{ @free_count = count(); }}
pid{pid}::realloc:entry {{ @realloc_count = count(); @realloc_bytes = sum(arg1); }}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{
    printa("malloc_count %@d\\n", @malloc_count);
    printa("malloc_bytes %@d\\n", @malloc_bytes);
    printa("free_count %@d\\n", @free_count);
    printa("realloc_count %@d\\n", @realloc_count);
    printa("realloc_bytes %@d\\n", @realloc_bytes);
    printa(@malloc_sizes);
    exit(0);
}}
"""
        output = await self._run_inline(script, duration + 2)
        summary = {}
        for line in output.splitlines():
            for key in ["malloc_count", "malloc_bytes", "free_count", "realloc_count", "realloc_bytes"]:
                if key in line:
                    m = re.search(r'(\d+)', line.split(key)[-1])
                    if m:
                        summary[key] = int(m.group(1))
        return {"pid": pid, "duration_s": duration, "summary": summary, "raw_output": output[:4000]}

    async def alloc_hotspots(self, session_id: str | None, duration: float, top_n: int) -> dict:
        if self.sip_enabled:
            return self._sip_error("alloc_hotspots")
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
pid{pid}::malloc:entry {{
    @bytes[ustack(5)] = sum(arg0); @counts[ustack(5)] = count();
}}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{
    trunc(@bytes, {top_n}); printa(@bytes);
    trunc(@counts, {top_n}); printa(@counts);
    exit(0);
}}
"""
        output = await self._run_inline(script, duration + 2)
        return {"pid": pid, "duration_s": duration, "raw_output": output[:8000]}

    # ---- I/O Analysis ----

    async def io_summary(self, session_id: str | None, duration: float) -> dict:
        if self.sip_enabled:
            session = self.sessions.get_default(session_id)
            pid = session.pid
            output = await self._run_fs_usage(pid, duration, "filesys")
            events = self._parse_fs_usage(output)
            # Summarize by FD
            fd_stats: dict[int, dict] = {}
            for e in events:
                fd = e.get("fd")
                if fd is None:
                    continue
                if fd not in fd_stats:
                    fd_stats[fd] = {"fd": fd, "ops": 0, "bytes": 0, "total_latency_us": 0, "syscalls": defaultdict(int)}
                fd_stats[fd]["ops"] += 1
                fd_stats[fd]["bytes"] += e.get("bytes", 0)
                fd_stats[fd]["total_latency_us"] += e.get("latency_us", 0)
                fd_stats[fd]["syscalls"][e["syscall"]] += 1
            for v in fd_stats.values():
                v["syscalls"] = dict(v["syscalls"])
            return {
                "pid": pid, "duration_s": duration,
                "io_by_fd": sorted(fd_stats.values(), key=lambda x: -x["ops"]),
                "total_events": len(events),
            }
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
syscall::read:entry, syscall::readv:entry, syscall::pread:entry
/pid == {pid}/ {{ self->ts = timestamp; self->fd = arg0; self->op = "read"; }}
syscall::write:entry, syscall::writev:entry, syscall::pwrite:entry
/pid == {pid}/ {{ self->ts = timestamp; self->fd = arg0; self->op = "write"; }}
syscall::read:return, syscall::readv:return, syscall::pread:return,
syscall::write:return, syscall::writev:return, syscall::pwrite:return
/pid == {pid} && self->ts/ {{
    this->delta = (timestamp - self->ts) / 1000;
    @io_count[self->op, self->fd] = count();
    @io_bytes[self->op, self->fd] = sum(arg1 > 0 ? arg1 : 0);
    @io_latency[self->op, self->fd] = avg(this->delta);
    self->ts = 0;
}}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{
    printa("IO|%s|%d|count=%@d\\n", @io_count);
    printa("IO|%s|%d|bytes=%@d\\n", @io_bytes);
    printa("IO|%s|%d|avg_us=%@d\\n", @io_latency);
    exit(0);
}}
"""
        output = await self._run_inline(script, duration + 2)
        io_data: dict[str, dict] = {}
        for line in output.splitlines():
            if not line.startswith("IO|"):
                continue
            parts = line.split("|")
            if len(parts) >= 4:
                op, fd = parts[1], parts[2]
                key = f"{op}:fd{fd}"
                if key not in io_data:
                    io_data[key] = {"op": op, "fd": int(fd)}
                kv = parts[3]
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    try:
                        io_data[key][k] = int(v)
                    except ValueError:
                        io_data[key][k] = v
        return {"pid": pid, "duration_s": duration, "io_operations": list(io_data.values()), "raw_output": output[:4000]}

    async def io_latency(self, session_id: str | None, duration: float, threshold_us: int) -> dict:
        if self.sip_enabled:
            session = self.sessions.get_default(session_id)
            pid = session.pid
            output = await self._run_fs_usage(pid, duration, "filesys")
            events = self._parse_fs_usage(output)
            slow = [e for e in events if e.get("latency_us", 0) >= threshold_us]
            return {
                "pid": pid, "duration_s": duration, "threshold_us": threshold_us,
                "slow_ops": slow[:500], "total_captured": len(slow),
            }
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
syscall::read:entry, syscall::readv:entry, syscall::pread:entry,
syscall::write:entry, syscall::writev:entry, syscall::pwrite:entry
/pid == {pid}/ {{ self->ts = timestamp; self->fd = arg0; }}
syscall::read:return, syscall::readv:return, syscall::pread:return,
syscall::write:return, syscall::writev:return, syscall::pwrite:return
/pid == {pid} && self->ts/ {{
    this->delta = (timestamp - self->ts) / 1000; self->ts = 0;
}}
syscall::read:return, syscall::readv:return, syscall::pread:return,
syscall::write:return, syscall::writev:return, syscall::pwrite:return
/this->delta >= {threshold_us} && pid == {pid}/ {{
    printf("SLOW_IO|%s|%d|%d|%d\\n", probefunc, self->fd, arg1, this->delta);
}}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{ exit(0); }}
"""
        output = await self._run_inline(script, duration + 2)
        events = []
        for line in output.splitlines():
            if line.startswith("SLOW_IO|"):
                parts = line.split("|")
                if len(parts) >= 5:
                    events.append({"syscall": parts[1], "fd": int(parts[2]), "bytes": int(parts[3]), "latency_us": int(parts[4])})
        return {"pid": pid, "duration_s": duration, "threshold_us": threshold_us, "slow_ops": events[:500], "total_captured": len(events)}

    # ---- Scheduling & Concurrency ----

    async def sched_summary(self, session_id: str | None, duration: float) -> dict:
        if self.sip_enabled:
            return self._sip_error("sched_summary")
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
sched:::off-cpu /pid == {pid}/ {{ self->off_ts = timestamp; @voluntary[tid] = count(); }}
sched:::on-cpu /pid == {pid} && self->off_ts/ {{
    this->off_time = (timestamp - self->off_ts) / 1000;
    @off_cpu_us[tid] = sum(this->off_time); @wakeup_latency[tid] = avg(this->off_time); self->off_ts = 0;
}}
sched:::on-cpu /pid == {pid}/ {{ self->on_ts = timestamp; }}
sched:::off-cpu /pid == {pid} && self->on_ts/ {{ @on_cpu_us[tid] = sum((timestamp - self->on_ts) / 1000); self->on_ts = 0; }}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{
    printa("ON_CPU|%d|%@d\\n", @on_cpu_us); printa("OFF_CPU|%d|%@d\\n", @off_cpu_us);
    printa("CTX_SW|%d|%@d\\n", @voluntary); printa("WAKEUP|%d|%@d\\n", @wakeup_latency);
    exit(0);
}}
"""
        output = await self._run_inline(script, duration + 2)
        threads: dict[int, dict] = {}
        for line in output.splitlines():
            for prefix, field in [("ON_CPU|", "on_cpu_us"), ("OFF_CPU|", "off_cpu_us"),
                                   ("CTX_SW|", "context_switches"), ("WAKEUP|", "avg_wakeup_us")]:
                if line.startswith(prefix):
                    parts = line.split("|")
                    if len(parts) >= 3:
                        tid = int(parts[1])
                        if tid not in threads:
                            threads[tid] = {"tid": tid}
                        threads[tid][field] = int(parts[2])
        return {"pid": pid, "duration_s": duration, "threads": list(threads.values()), "raw_output": output[:4000]}

    async def lock_contention(self, session_id: str | None, duration: float, threshold_us: int) -> dict:
        if self.sip_enabled:
            return self._sip_error("lock_contention")
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
syscall::psynch_mutexwait:entry /pid == {pid}/ {{ self->lock_ts = timestamp; self->lock_addr = arg0; }}
syscall::psynch_mutexwait:return /pid == {pid} && self->lock_ts/ {{
    this->delta = (timestamp - self->lock_ts) / 1000; self->lock_ts = 0;
}}
syscall::psynch_mutexwait:return /this->delta >= {threshold_us} && pid == {pid}/ {{
    printf("LOCK|%d|%x|%d\\n", tid, self->lock_addr, this->delta);
}}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{ exit(0); }}
"""
        output = await self._run_inline(script, duration + 2)
        events = []
        for line in output.splitlines():
            if line.startswith("LOCK|"):
                parts = line.split("|")
                if len(parts) >= 4:
                    events.append({"tid": int(parts[1]), "lock_addr": parts[2], "wait_us": int(parts[3])})
        return {"pid": pid, "duration_s": duration, "threshold_us": threshold_us, "contention_events": events[:500], "raw_output": output[:4000]}

    async def offcpu(self, session_id: str | None, duration: float, min_us: int) -> dict:
        if self.sip_enabled:
            return self._sip_error("offcpu")
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
sched:::off-cpu /pid == {pid}/ {{ self->off_ts = timestamp; }}
sched:::on-cpu /pid == {pid} && self->off_ts/ {{
    this->delta = (timestamp - self->off_ts) / 1000; self->off_ts = 0;
}}
sched:::on-cpu /this->delta >= {min_us} && pid == {pid}/ {{ @stacks[ustack()] = sum(this->delta); }}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{ printa(@stacks); exit(0); }}
"""
        output = await self._run_inline(script, duration + 2)
        return {"pid": pid, "duration_s": duration, "min_us": min_us, "raw_output": output[:8000]}

    # ---- Tick/Frame Analysis ----

    async def tick_summary(self, session_id: str | None, tick_name: str, duration: float) -> dict:
        if self.sip_enabled:
            return self._sip_error("tick_summary (pid provider blocked)")
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined. Use ctrace_define_tick first.")
        tick = session.ticks[tick_name]
        func = tick.function
        script = f"""
pid{pid}::{func}:entry {{ self->tick_start = timestamp; self->tick_syscalls = 0; self->tick_allocs = 0; }}
syscall:::entry /pid == {pid} && self->tick_start/ {{ self->tick_syscalls++; }}
pid{pid}::malloc:entry /self->tick_start/ {{ self->tick_allocs++; }}
pid{pid}::{func}:return /self->tick_start/ {{
    this->dur = (timestamp - self->tick_start) / 1000;
    @durations = quantize(this->dur); @count = count(); @total = sum(this->dur);
    @min_d = min(this->dur); @max_d = max(this->dur); @avg_d = avg(this->dur);
    @avg_syscalls = avg(self->tick_syscalls); @avg_allocs = avg(self->tick_allocs);
    self->tick_start = 0;
}}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{
    printa("tick_count %@d\\n", @count); printa("total_us %@d\\n", @total);
    printa("min_us %@d\\n", @min_d); printa("max_us %@d\\n", @max_d);
    printa("avg_us %@d\\n", @avg_d);
    printa("avg_syscalls %@d\\n", @avg_syscalls); printa("avg_allocs %@d\\n", @avg_allocs);
    printa(@durations); exit(0);
}}
"""
        output = await self._run_inline(script, duration + 2)
        stats = {}
        for line in output.splitlines():
            for key in ["tick_count", "total_us", "min_us", "max_us", "avg_us", "avg_syscalls", "avg_allocs"]:
                if key in line:
                    m = re.search(r'(-?\d+)', line.split(key)[-1])
                    if m:
                        stats[key] = int(m.group(1))
        return {"pid": pid, "tick": tick_name, "function": func, "duration_s": duration, "stats": stats, "raw_output": output[:4000]}

    async def tick_outliers(self, session_id: str | None, tick_name: str, duration: float, threshold_us: int) -> dict:
        if self.sip_enabled:
            return self._sip_error("tick_outliers (pid provider blocked)")
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined.")
        tick = session.ticks[tick_name]
        func = tick.function
        script = f"""
pid{pid}::{func}:entry {{ self->tick_start = timestamp; self->tick_syscalls = 0; self->tick_allocs = 0; self->tick_alloc_bytes = 0; }}
syscall:::entry /pid == {pid} && self->tick_start/ {{ self->tick_syscalls++; }}
pid{pid}::malloc:entry /self->tick_start/ {{ self->tick_allocs++; self->tick_alloc_bytes += arg0; }}
pid{pid}::{func}:return /self->tick_start/ {{
    this->dur = (timestamp - self->tick_start) / 1000; self->tick_start = 0; @total_ticks = count();
}}
pid{pid}::{func}:return /this->dur >= {threshold_us}/ {{
    printf("OUTLIER|%d|%d|%d|%d\\n", this->dur, self->tick_syscalls, self->tick_allocs, self->tick_alloc_bytes);
    @outlier_count = count();
}}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{
    printa("TOTAL_TICKS %@d\\n", @total_ticks); printa("OUTLIER_COUNT %@d\\n", @outlier_count); exit(0);
}}
"""
        output = await self._run_inline(script, duration + 2)
        outliers = []
        for line in output.splitlines():
            if line.startswith("OUTLIER|"):
                parts = line.split("|")
                if len(parts) >= 5:
                    outliers.append({"duration_us": int(parts[1]), "syscalls": int(parts[2]), "allocs": int(parts[3]), "alloc_bytes": int(parts[4])})
        return {"pid": pid, "tick": tick_name, "function": func, "threshold_us": threshold_us, "duration_s": duration, "outliers": outliers[:200], "total_outliers": len(outliers), "raw_output": output[:4000]}

    async def tick_compare(self, session_id: str | None, tick_name: str, duration: float) -> dict:
        if self.sip_enabled:
            return self._sip_error("tick_compare (pid provider blocked)")
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined.")
        tick = session.ticks[tick_name]
        func = tick.function
        script = f"""
pid{pid}::{func}:entry {{ self->tick_start = timestamp; self->tick_syscalls = 0; self->tick_allocs = 0; }}
syscall:::entry /pid == {pid} && self->tick_start/ {{ self->tick_syscalls++; }}
pid{pid}::malloc:entry /self->tick_start/ {{ self->tick_allocs++; }}
pid{pid}::{func}:return /self->tick_start/ {{
    this->dur = (timestamp - self->tick_start) / 1000;
    printf("TICK|%d|%d|%d\\n", this->dur, self->tick_syscalls, self->tick_allocs);
    self->tick_start = 0;
}}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{ exit(0); }}
"""
        output = await self._run_inline(script, duration + 2)
        ticks = []
        for line in output.splitlines():
            if line.startswith("TICK|"):
                parts = line.split("|")
                if len(parts) >= 4:
                    ticks.append({"duration_us": int(parts[1]), "syscalls": int(parts[2]), "allocs": int(parts[3])})
        if not ticks:
            return {"pid": pid, "tick": tick_name, "error": "No ticks captured", "raw_output": output[:4000]}
        ticks.sort(key=lambda t: t["duration_us"])
        n = len(ticks)
        p50_idx = n // 2
        p99_idx = min(int(n * 0.99), n - 1)
        fast = ticks[:p50_idx + 1] if p50_idx > 0 else ticks[:1]
        slow = ticks[p99_idx:] if p99_idx < n else ticks[-1:]
        def avg_stats(group):
            if not group:
                return {}
            return {"count": len(group), "avg_duration_us": sum(t["duration_us"] for t in group) // len(group),
                    "avg_syscalls": round(sum(t["syscalls"] for t in group) / len(group), 1),
                    "avg_allocs": round(sum(t["allocs"] for t in group) / len(group), 1)}
        return {"pid": pid, "tick": tick_name, "function": func, "duration_s": duration, "total_ticks": n,
                "fast_ticks_p50": avg_stats(fast), "slow_ticks_p99": avg_stats(slow),
                "p50_duration_us": ticks[p50_idx]["duration_us"], "p99_duration_us": ticks[p99_idx]["duration_us"]}

    # ---- General ----

    async def probe(self, session_id: str | None, script: str, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = script.replace("$target", str(pid))
        output = await self._run_inline(script, duration + 2)
        return {"pid": pid, "duration_s": duration, "output": output[:8000]}

    async def snapshot(self, session_id: str | None, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            # SIP-compatible snapshot: fs_usage for syscalls + profile for CPU
            fs_output, dtrace_output = await asyncio.gather(
                self._run_fs_usage(pid, duration),
                self._run_inline(f"""
profile-997 /pid == {pid}/ {{ @cpu[umod(arg1)] = count(); }}
magmalloc{pid}:::allocRegion {{ @alloc_regions = count(); @alloc_bytes = sum(arg0); }}
magmalloc{pid}:::deallocRegion {{ @dealloc_regions = count(); }}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{
    trunc(@cpu, 10); printa(@cpu);
    printa("alloc_regions %@d\\n", @alloc_regions);
    printa("alloc_bytes %@d\\n", @alloc_bytes);
    printa("dealloc_regions %@d\\n", @dealloc_regions);
    exit(0);
}}
""", duration + 2),
            )
            events = self._parse_fs_usage(fs_output)
            syscall_summary = self._summarize_fs_usage(events, 10)
            status = session.status_info()
            return {
                "pid": pid, "duration_s": duration,
                "process_status": status,
                "ticks_defined": list(session.ticks.keys()),
                **syscall_summary,
                "dtrace_output": dtrace_output[:3000],
            }

        tick_probes = ""
        tick_report = ""
        for name, tick in session.ticks.items():
            tick_probes += f"""
pid{pid}::{tick.function}:entry {{ self->snap_tick_start_{name} = timestamp; }}
pid{pid}::{tick.function}:return /self->snap_tick_start_{name}/ {{
    this->dur = (timestamp - self->snap_tick_start_{name}) / 1000;
    @tick_{name}_dur = quantize(this->dur); @tick_{name}_count = count();
    self->snap_tick_start_{name} = 0;
}}
"""
            tick_report += f'    printa("TICK|{name}|count=%@d\\n", @tick_{name}_count);\n'
        script = f"""
syscall:::entry /pid == {pid}/ {{ self->ts = timestamp; @sc_count[probefunc] = count(); }}
syscall:::return /pid == {pid} && self->ts/ {{ @sc_lat[probefunc] = sum((timestamp - self->ts) / 1000); self->ts = 0; }}
pid{pid}::malloc:entry {{ @alloc_count = count(); @alloc_bytes = sum(arg0); }}
sched:::off-cpu /pid == {pid}/ {{ self->snap_off = timestamp; }}
sched:::on-cpu /pid == {pid} && self->snap_off/ {{ @sched_delays = quantize((timestamp - self->snap_off) / 1000); self->snap_off = 0; }}
{tick_probes}
tick-1s {{ secs++; }}
tick-1s /secs >= {int(duration)}/ {{
    trunc(@sc_count, 10); trunc(@sc_lat, 10);
    printa("SYSCALL|%s|count=%@d\\n", @sc_count); printa("SYSCALL|%s|lat_us=%@d\\n", @sc_lat);
    printa("ALLOC|count=%@d\\n", @alloc_count); printa("ALLOC|bytes=%@d\\n", @alloc_bytes);
{tick_report}    exit(0);
}}
"""
        output = await self._run_inline(script, duration + 2)
        status = session.status_info()
        return {"pid": pid, "duration_s": duration, "process_status": status, "ticks_defined": list(session.ticks.keys()), "raw_output": output[:6000]}
