"""macOS dtrace backend.

Handles both SIP-enabled and SIP-disabled environments.
With SIP on, syscall/pid/sched probes are unavailable — we fall back to
fs_usage (per-syscall tracing), profile sampling, and the magmalloc provider.
"""

from __future__ import annotations

import asyncio
import json
import re
import signal
import subprocess
from collections import defaultdict
from typing import Any

from ctrace.backend import Backend
from ctrace.schema import Capabilities, TraceEvent

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
    def backend_name(self) -> str:
        return "dtrace"

    def _default_capabilities(self) -> Capabilities:
        return self._dtrace_capabilities()

    def _dtrace_capabilities(self) -> Capabilities:
        return Capabilities(
            has_user_stacks=True,
            has_kernel_stacks=False,
            has_args=True,
            has_retval=True,
            has_tid=True,
            timing_source="event",
        )

    def _fs_usage_capabilities(self) -> Capabilities:
        return Capabilities(
            has_user_stacks=False,
            has_kernel_stacks=False,
            has_args=True,
            has_retval=False,
            has_tid=False,
            timing_source="event",
        )

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

    def _sip_error(self, tool_name: str, session_id: str = "", pid: int = 0, duration_s: float = 0.0) -> dict:
        error_msg = f"{tool_name}: {SIP_MSG}"
        return self._wrap(
            tool=f"ctrace_{tool_name}",
            session_id=session_id,
            pid=pid,
            duration_s=duration_s,
            errors=[error_msg],
            capabilities=Capabilities(
                has_user_stacks=False,
                has_kernel_stacks=False,
                has_args=False,
                has_retval=False,
                has_tid=False,
                timing_source="derived",
            ),
        )

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
            output = await self._run_fs_usage(pid, duration)
            fs_events = self._parse_fs_usage(output)
            summary = self._summarize_fs_usage(fs_events, top_n)
            agg = {"syscall_by_name": summary.get("syscalls", [])}
            return self._wrap(
                tool="ctrace_syscall_summary",
                session_id=session.session_id,
                pid=pid,
                duration_s=duration,
                capabilities=self._fs_usage_capabilities(),
                aggregates=agg,
            )

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
        top = counts[:top_n]
        return self._wrap(
            tool="ctrace_syscall_summary",
            session_id=session.session_id,
            pid=pid,
            duration_s=duration,
            capabilities=self._dtrace_capabilities(),
            aggregates={"syscall_by_name": top},
            raw_output=output[:4000],
        )

    async def syscall_trace(self, session_id: str | None, duration: float, syscalls: list[str] | None, min_latency_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            output = await self._run_fs_usage(pid, duration)
            fs_events = self._parse_fs_usage(output)
            filtered = []
            for e in fs_events:
                if syscalls and e["syscall"] not in syscalls:
                    continue
                if e.get("latency_us", 0) < min_latency_us:
                    continue
                filtered.append(e)
            trace_events = [
                TraceEvent(
                    ts_ns=None, category="syscall", name=e["syscall"], phase="complete",
                    duration_us=e.get("latency_us", 0), status="ok",
                    fields={k: e[k] for k in ("fd", "bytes", "path") if k in e},
                )
                for e in filtered[:500]
            ]
            return self._wrap(
                tool="ctrace_syscall_trace", session_id=session.session_id, pid=pid,
                duration_s=duration, capabilities=self._fs_usage_capabilities(),
                events=trace_events,
            )

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
        parsed = self._parse_delimited(output, ["_marker", "syscall", "arg0", "arg1", "retval", "latency_us"])
        cleaned = [
            {k: e[k] for k in ["syscall", "arg0", "arg1", "retval", "latency_us"] if k in e}
            for e in parsed if e.get("_marker") == "TRACE"
        ]
        trace_events = [
            TraceEvent(
                ts_ns=None, category="syscall", name=e.get("syscall", ""), phase="complete",
                duration_us=int(e.get("latency_us", 0)), status="ok",
                fields={k: e[k] for k in ("arg0", "arg1", "retval") if k in e},
            )
            for e in cleaned[:500]
        ]
        return self._wrap(
            tool="ctrace_syscall_trace", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=self._dtrace_capabilities(),
            events=trace_events,
        )

    # ---- Memory Analysis ----

    async def alloc_summary(self, session_id: str | None, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
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
            return self._wrap(
                tool="ctrace_alloc_summary", session_id=session.session_id, pid=pid,
                duration_s=duration, aggregates={"alloc_stats": summary},
                raw_output=output[:4000],
                capabilities=Capabilities(
                    has_user_stacks=False, has_kernel_stacks=False, has_args=False,
                    has_retval=False, has_tid=False, timing_source="derived",
                ),
                warnings=["SIP enabled — showing memory region allocations (not individual malloc calls)"],
            )

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
        return self._wrap(
            tool="ctrace_alloc_summary", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=self._dtrace_capabilities(),
            aggregates={"alloc_stats": summary}, raw_output=output[:4000],
        )

    async def alloc_hotspots(self, session_id: str | None, duration: float, top_n: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            return self._sip_error("alloc_hotspots", session.session_id, pid, duration)
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
        caps = self._dtrace_capabilities()
        caps["has_user_stacks"] = True
        return self._wrap(
            tool="ctrace_alloc_hotspots", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=caps, raw_output=output[:8000],
        )

    # ---- I/O Analysis ----

    async def io_summary(self, session_id: str | None, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            output = await self._run_fs_usage(pid, duration, "filesys")
            fs_events = self._parse_fs_usage(output)
            fd_stats: dict[int, dict] = {}
            for e in fs_events:
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
            io_by_fd = sorted(fd_stats.values(), key=lambda x: -x["ops"])
            trace_events = [
                TraceEvent(
                    ts_ns=None, category="io", name=e["syscall"], phase="complete",
                    duration_us=e.get("latency_us", 0), status="ok",
                    fields={k: e[k] for k in ("fd", "bytes", "path") if k in e},
                )
                for e in fs_events[:500]
            ]
            return self._wrap(
                tool="ctrace_io_summary", session_id=session.session_id, pid=pid,
                duration_s=duration, capabilities=self._fs_usage_capabilities(),
                events=trace_events, aggregates={"io_by_fd": io_by_fd},
            )

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
        io_ops = list(io_data.values())
        return self._wrap(
            tool="ctrace_io_summary", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=self._dtrace_capabilities(),
            aggregates={"io_by_fd": io_ops}, raw_output=output[:4000],
        )

    async def io_latency(self, session_id: str | None, duration: float, threshold_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            output = await self._run_fs_usage(pid, duration, "filesys")
            fs_events = self._parse_fs_usage(output)
            slow = [e for e in fs_events if e.get("latency_us", 0) >= threshold_us]
            trace_events = [
                TraceEvent(
                    ts_ns=None, category="io", name=e["syscall"], phase="complete",
                    duration_us=e.get("latency_us", 0), status="ok",
                    fields={k: e[k] for k in ("fd", "bytes", "path") if k in e},
                    labels=["slow"],
                )
                for e in slow[:500]
            ]
            return self._wrap(
                tool="ctrace_io_latency", session_id=session.session_id, pid=pid,
                duration_s=duration, capabilities=self._fs_usage_capabilities(),
                events=trace_events,
            )

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
        parsed_events = []
        for line in output.splitlines():
            if line.startswith("SLOW_IO|"):
                parts = line.split("|")
                if len(parts) >= 5:
                    parsed_events.append({"syscall": parts[1], "fd": int(parts[2]), "bytes": int(parts[3]), "latency_us": int(parts[4])})
        trace_events = [
            TraceEvent(
                ts_ns=None, category="io", name=e["syscall"], phase="complete",
                duration_us=e["latency_us"], status="ok",
                fields={"fd": e["fd"], "bytes": e["bytes"]}, labels=["slow"],
            )
            for e in parsed_events[:500]
        ]
        return self._wrap(
            tool="ctrace_io_latency", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=self._dtrace_capabilities(),
            events=trace_events,
        )

    # ---- Scheduling & Concurrency ----

    async def sched_summary(self, session_id: str | None, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            return self._sip_error("sched_summary", session.session_id, pid, duration)
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
        thread_list = list(threads.values())
        return self._wrap(
            tool="ctrace_sched_summary", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=self._dtrace_capabilities(),
            aggregates={"threads": thread_list}, raw_output=output[:4000],
        )

    async def lock_contention(self, session_id: str | None, duration: float, threshold_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            return self._sip_error("lock_contention", session.session_id, pid, duration)
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
        trace_events = [
            TraceEvent(
                ts_ns=None, category="lock", name="psynch_mutexwait", phase="complete",
                tid=e["tid"], duration_us=e["wait_us"], status="ok",
                fields={"lock_addr": e["lock_addr"]},
            )
            for e in events[:500]
        ]
        return self._wrap(
            tool="ctrace_lock_contention", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=self._dtrace_capabilities(),
            events=trace_events, raw_output=output[:4000],
        )

    async def offcpu(self, session_id: str | None, duration: float, min_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            return self._sip_error("offcpu", session.session_id, pid, duration)
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
        caps = self._dtrace_capabilities()
        caps["has_user_stacks"] = True
        return self._wrap(
            tool="ctrace_offcpu", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=caps, raw_output=output[:8000],
        )

    # ---- Tick/Frame Analysis ----

    async def tick_summary(self, session_id: str | None, tick_name: str, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            return self._sip_error("tick_summary", session.session_id, pid, duration)
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined. Use ctrace_define_tick first.")
        tick = session.ticks[tick_name]
        func = tick.function
        thread_pred = f'/curthread->t_name == "{tick.thread_filter}"/ ' if tick.thread_filter else ""
        script = f"""
pid{pid}::{func}:entry {thread_pred}{{ self->tick_start = timestamp; self->tick_syscalls = 0; self->tick_allocs = 0; }}
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
        return self._wrap(
            tool="ctrace_tick_summary", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=self._dtrace_capabilities(),
            aggregates={"tick_stats": stats}, raw_output=output[:4000],
        )

    async def tick_outliers(self, session_id: str | None, tick_name: str, duration: float, threshold_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            return self._sip_error("tick_outliers", session.session_id, pid, duration)
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined.")
        tick = session.ticks[tick_name]
        func = tick.function
        thread_pred = f'/curthread->t_name == "{tick.thread_filter}"/ ' if tick.thread_filter else ""
        script = f"""
pid{pid}::{func}:entry {thread_pred}{{ self->tick_start = timestamp; self->tick_syscalls = 0; self->tick_allocs = 0; self->tick_alloc_bytes = 0; }}
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
        trace_events = [
            TraceEvent(
                ts_ns=None, category="tick", name=tick_name, phase="complete",
                duration_us=o["duration_us"], status="ok",
                fields={k: o[k] for k in ("syscalls", "allocs", "alloc_bytes") if k in o},
                labels=["outlier"],
            )
            for o in outliers[:200]
        ]
        return self._wrap(
            tool="ctrace_tick_outliers", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=self._dtrace_capabilities(),
            events=trace_events, raw_output=output[:4000],
        )

    async def tick_compare(self, session_id: str | None, tick_name: str, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if self.sip_enabled:
            return self._sip_error("tick_compare", session.session_id, pid, duration)
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined.")
        tick = session.ticks[tick_name]
        func = tick.function
        thread_pred = f'/curthread->t_name == "{tick.thread_filter}"/ ' if tick.thread_filter else ""
        script = f"""
pid{pid}::{func}:entry {thread_pred}{{ self->tick_start = timestamp; self->tick_syscalls = 0; self->tick_allocs = 0; }}
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
            return self._wrap(
                tool="ctrace_tick_compare", session_id=session.session_id, pid=pid,
                duration_s=duration, capabilities=self._dtrace_capabilities(),
                errors=["No ticks captured"], raw_output=output[:4000],
            )
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
        comparison = {
            "total_ticks": n, "p50_duration_us": ticks[p50_idx]["duration_us"],
            "p99_duration_us": ticks[p99_idx]["duration_us"],
            "fast_ticks_p50": avg_stats(fast), "slow_ticks_p99": avg_stats(slow),
        }
        return self._wrap(
            tool="ctrace_tick_compare", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=self._dtrace_capabilities(),
            aggregates={"tick_comparison": comparison},
        )

    # ---- General ----

    async def probe(self, session_id: str | None, script: str, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = script.replace("$target", str(pid))
        output = await self._run_inline(script, duration + 2)
        return self._wrap(
            tool="ctrace_probe", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=self._dtrace_capabilities(),
            raw_output=output[:8000],
        )

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
            fs_events = self._parse_fs_usage(fs_output)
            syscall_summary = self._summarize_fs_usage(fs_events, 10)
            status = session.status_info()
            return self._wrap(
                tool="ctrace_snapshot", session_id=session.session_id, pid=pid,
                duration_s=duration, capabilities=self._fs_usage_capabilities(),
                aggregates={"syscall_summary": syscall_summary},
                raw_output=dtrace_output[:3000],
            )

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
        return self._wrap(
            tool="ctrace_snapshot", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=self._dtrace_capabilities(),
            raw_output=output[:6000],
        )

    # ---- macOS thread name lookup ----

    def threads(self, session_id: str | None) -> dict:
        """List threads using libproc proc_pidinfo via sudo.

        On macOS, psutil.Process.threads() and libproc proc_pidinfo both
        require task_for_pid privileges. We shell out to sudo python3 to
        run the query (sudo is already configured for dtrace).
        """
        session = self.sessions.get_default(session_id)
        pid = session.pid
        return self._macos_threads_via_sudo(pid)

    @staticmethod
    def _macos_threads_via_sudo(pid: int) -> dict:
        """Return thread list for *pid* using proc_pidinfo via sudo."""
        helper = _MACOS_THREAD_HELPER.replace("TARGET_PID", str(pid))
        result = subprocess.run(
            ["sudo", "-n", "python3", "-c", helper],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise ValueError(
                f"Cannot list threads for pid {pid}: {result.stderr.strip()}"
            )
        thread_list = json.loads(result.stdout)
        return {
            "pid": pid,
            "thread_count": len(thread_list),
            "threads": thread_list,
        }


# Inline Python script executed via sudo to list threads using libproc.
# Uses three proc_pidinfo flavors:
#   4  (PROC_PIDTASKINFO)       — get thread count
#   28 (PROC_PIDLISTTHREADIDS)  — get real thread IDs (matches dtrace tid)
#   6  (PROC_PIDLISTTHREADS)    — get thread handles (Mach port names)
#   5  (PROC_PIDTHREADINFO)     — per-thread name + CPU times (keyed by handle)
_MACOS_THREAD_HELPER = '''
import ctypes, ctypes.util, json, sys

pid = TARGET_PID
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
f = libc.proc_pidinfo
f.restype = ctypes.c_int
f.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]

class PTI(ctypes.Structure):
    _fields_ = [
        ("v", ctypes.c_uint64), ("r", ctypes.c_uint64),
        ("tu", ctypes.c_uint64), ("ts", ctypes.c_uint64),
        ("thu", ctypes.c_uint64), ("ths", ctypes.c_uint64),
        ("pol", ctypes.c_int32), ("flt", ctypes.c_int32),
        ("pgi", ctypes.c_int32), ("cow", ctypes.c_int32),
        ("ms", ctypes.c_int32), ("mr", ctypes.c_int32),
        ("sm", ctypes.c_int32), ("su", ctypes.c_int32),
        ("csw", ctypes.c_int32), ("threadnum", ctypes.c_int32),
        ("running", ctypes.c_int32), ("pri", ctypes.c_int32),
    ]

ti = PTI()
if f(pid, 4, 0, ctypes.byref(ti), ctypes.sizeof(ti)) <= 0:
    print("[]"); sys.exit(0)
n = ti.threadnum

tids = (ctypes.c_uint64 * (n * 2))()
n_tids = f(pid, 28, 0, tids, n * 2 * 8) // 8

handles = (ctypes.c_uint64 * (n * 2))()
n_handles = f(pid, 6, 0, handles, n * 2 * 8) // 8

class T(ctypes.Structure):
    _fields_ = [
        ("user", ctypes.c_uint64), ("sys", ctypes.c_uint64),
        ("cpu", ctypes.c_int32), ("pol", ctypes.c_int32),
        ("run", ctypes.c_int32), ("flg", ctypes.c_int32),
        ("slp", ctypes.c_int32), ("cur", ctypes.c_int32),
        ("pri", ctypes.c_int32), ("max", ctypes.c_int32),
        ("name", ctypes.c_char * 64),
    ]

out = []
for i in range(min(n_tids, n_handles)):
    handle = int(handles[i])
    info = T()
    rc = f(pid, 5, handle, ctypes.byref(info), ctypes.sizeof(info))
    if rc > 0:
        nm = info.name.decode("utf-8", errors="replace").rstrip("\\x00")
        entry = {"tid": int(tids[i]), "user_time_s": round(info.user / 1e9, 3), "system_time_s": round(info.sys / 1e9, 3)}
        if nm:
            entry["name"] = nm
        out.append(entry)
print(json.dumps(out))
'''
