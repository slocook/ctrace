"""Linux bpftrace backend."""

from __future__ import annotations

import re
import subprocess
from typing import Any

from ctrace.backend import Backend
from ctrace.schema import Capabilities, TraceEvent


class BpftraceBackend(Backend):

    def __init__(self) -> None:
        super().__init__()
        self._libc_path: str | None = None

    @property
    def backend_name(self) -> str:
        return "bpftrace"

    def _default_capabilities(self) -> Capabilities:
        return Capabilities(
            has_user_stacks=True,
            has_kernel_stacks=True,
            has_args=True,
            has_retval=True,
            has_tid=True,
            timing_source="event",
        )

    def tracer_cmd(self) -> list[str]:
        return ["sudo", "bpftrace"]

    def script_ext(self) -> str:
        return ".bt"

    def _script_args(self, script: str) -> list[str]:
        return ["-e", script]

    def _get_libc(self) -> str:
        if self._libc_path:
            return self._libc_path
        try:
            result = subprocess.run(
                ["ldconfig", "-p"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "libc.so.6" in line and ("x86_64" in line or "x86-64" in line):
                    path = line.split("=>")[-1].strip()
                    self._libc_path = path
                    return path
                if "libc.so.6" in line and "aarch64" in line:
                    path = line.split("=>")[-1].strip()
                    self._libc_path = path
                    return path
            # Fallback: try common path
            for line in result.stdout.splitlines():
                if "libc.so.6" in line:
                    path = line.split("=>")[-1].strip()
                    self._libc_path = path
                    return path
        except Exception:
            pass
        self._libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
        return self._libc_path

    async def syscall_summary(self, session_id: str | None, duration: float, top_n: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
tracepoint:syscalls:sys_enter_* /pid == {pid}/ {{
    @start[tid] = nsecs;
    @counts[probe] = count();
}}

tracepoint:syscalls:sys_exit_* /pid == {pid} && @start[tid]/ {{
    $dur = (nsecs - @start[tid]) / 1000;
    @latency[probe] = sum($dur);
    delete(@start[tid]);
}}

interval:s:{int(duration)} {{
    print(@counts, {top_n});
    print(@latency, {top_n});
    exit();
}}
"""
        output = await self.run_script(script, duration + 2)
        return self._wrap(
            tool="ctrace_syscall_summary", session_id=session.session_id, pid=pid,
            duration_s=duration, raw_output=output[:4000],
        )

    async def syscall_trace(self, session_id: str | None, duration: float, syscalls: list[str] | None, min_latency_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if syscalls:
            entry_probes = ",\n".join(f"tracepoint:syscalls:sys_enter_{s}" for s in syscalls)
            exit_probes = ",\n".join(f"tracepoint:syscalls:sys_exit_{s}" for s in syscalls)
        else:
            entry_probes = "tracepoint:syscalls:sys_enter_*"
            exit_probes = "tracepoint:syscalls:sys_exit_*"
        script = f"""
{entry_probes} /pid == {pid}/ {{
    @start[tid] = nsecs;
}}

{exit_probes} /pid == {pid} && @start[tid]/ {{
    $dur = (nsecs - @start[tid]) / 1000;
    delete(@start[tid]);
    if ($dur >= {min_latency_us}) {{
        printf("TRACE|%s|%d\\n", probe, $dur);
    }}
}}

interval:s:{int(duration)} {{ exit(); }}
"""
        output = await self.run_script(script, duration + 2)
        events = []
        for line in output.splitlines():
            if line.startswith("TRACE|"):
                parts = line.split("|")
                if len(parts) >= 3:
                    probe_name = parts[1]
                    syscall_name = probe_name.split("sys_exit_")[-1] if "sys_exit_" in probe_name else probe_name
                    events.append({
                        "syscall": syscall_name,
                        "probe": probe_name,
                        "latency_us": int(parts[2]),
                    })
        trace_events = [
            TraceEvent(
                ts_ns=None, category="syscall", name=e["syscall"], phase="complete",
                duration_us=e["latency_us"], status="ok",
            )
            for e in events[:500]
        ]
        return self._wrap(
            tool="ctrace_syscall_trace", session_id=session.session_id, pid=pid,
            duration_s=duration, events=trace_events,
        )

    async def alloc_summary(self, session_id: str | None, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        libc = self._get_libc()
        script = f"""
uprobe:{libc}:malloc /pid == {pid}/ {{
    @malloc_count = count();
    @malloc_bytes = sum(arg0);
    @malloc_sizes = hist(arg0);
}}

uprobe:{libc}:free /pid == {pid}/ {{
    @free_count = count();
}}

uprobe:{libc}:realloc /pid == {pid}/ {{
    @realloc_count = count();
    @realloc_bytes = sum(arg1);
}}

interval:s:{int(duration)} {{
    print(@malloc_count);
    print(@malloc_bytes);
    print(@free_count);
    print(@realloc_count);
    print(@realloc_bytes);
    print(@malloc_sizes);
    exit();
}}
"""
        output = await self.run_script(script, duration + 2)
        return self._wrap(
            tool="ctrace_alloc_summary", session_id=session.session_id, pid=pid,
            duration_s=duration, raw_output=output[:4000],
        )

    async def alloc_hotspots(self, session_id: str | None, duration: float, top_n: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        libc = self._get_libc()
        script = f"""
uprobe:{libc}:malloc /pid == {pid}/ {{
    @bytes[ustack(5)] = sum(arg0);
    @counts[ustack(5)] = count();
}}

interval:s:{int(duration)} {{
    print(@bytes, {top_n});
    print(@counts, {top_n});
    exit();
}}
"""
        output = await self.run_script(script, duration + 2)
        return self._wrap(
            tool="ctrace_alloc_hotspots", session_id=session.session_id, pid=pid,
            duration_s=duration, raw_output=output[:8000],
        )

    async def io_summary(self, session_id: str | None, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
tracepoint:syscalls:sys_enter_read,
tracepoint:syscalls:sys_enter_write /pid == {pid}/ {{
    @io_start[tid] = nsecs;
    @io_fd[tid] = args.fd;
}}

tracepoint:syscalls:sys_exit_read,
tracepoint:syscalls:sys_exit_write /pid == {pid} && @io_start[tid]/ {{
    $dur = (nsecs - @io_start[tid]) / 1000;
    printf("IO|%s|%d|%d|%d\\n", probe, @io_fd[tid], args.ret > 0 ? args.ret : 0, $dur);
    delete(@io_start[tid]);
    delete(@io_fd[tid]);
}}

interval:s:{int(duration)} {{ exit(); }}
"""
        output = await self.run_script(script, duration + 2)
        io_data = []
        for line in output.splitlines():
            if line.startswith("IO|"):
                parts = line.split("|")
                if len(parts) >= 5:
                    io_data.append({
                        "probe": parts[1],
                        "fd": int(parts[2]),
                        "bytes": int(parts[3]),
                        "latency_us": int(parts[4]),
                    })
        trace_events = [
            TraceEvent(
                ts_ns=None, category="io", name=e["probe"], phase="complete",
                duration_us=e["latency_us"], status="ok",
                fields={"fd": e["fd"], "bytes": e["bytes"]},
            )
            for e in io_data[:500]
        ]
        return self._wrap(
            tool="ctrace_io_summary", session_id=session.session_id, pid=pid,
            duration_s=duration, events=trace_events,
        )

    async def io_latency(self, session_id: str | None, duration: float, threshold_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
tracepoint:syscalls:sys_enter_read,
tracepoint:syscalls:sys_enter_readv,
tracepoint:syscalls:sys_enter_pread64,
tracepoint:syscalls:sys_enter_write,
tracepoint:syscalls:sys_enter_writev,
tracepoint:syscalls:sys_enter_pwrite64 /pid == {pid}/ {{
    @io_start[tid] = nsecs;
    @io_fd[tid] = args.fd;
}}

tracepoint:syscalls:sys_exit_read,
tracepoint:syscalls:sys_exit_readv,
tracepoint:syscalls:sys_exit_pread64,
tracepoint:syscalls:sys_exit_write,
tracepoint:syscalls:sys_exit_writev,
tracepoint:syscalls:sys_exit_pwrite64 /pid == {pid} && @io_start[tid]/ {{
    $dur = (nsecs - @io_start[tid]) / 1000;
    delete(@io_start[tid]);
    if ($dur >= {threshold_us}) {{
        printf("SLOW_IO|%s|%d|%d|%d\\n", probe, @io_fd[tid], args.ret, $dur);
    }}
    delete(@io_fd[tid]);
}}

interval:s:{int(duration)} {{ exit(); }}
"""
        output = await self.run_script(script, duration + 2)
        events = []
        for line in output.splitlines():
            if line.startswith("SLOW_IO|"):
                parts = line.split("|")
                if len(parts) >= 5:
                    events.append({
                        "probe": parts[1],
                        "fd": int(parts[2]),
                        "bytes": int(parts[3]),
                        "latency_us": int(parts[4]),
                    })
        trace_events = [
            TraceEvent(
                ts_ns=None, category="io", name=e["probe"], phase="complete",
                duration_us=e["latency_us"], status="ok",
                fields={"fd": e["fd"], "bytes": e["bytes"]}, labels=["slow"],
            )
            for e in events[:500]
        ]
        return self._wrap(
            tool="ctrace_io_latency", session_id=session.session_id, pid=pid,
            duration_s=duration, events=trace_events,
        )

    async def sched_summary(self, session_id: str | None, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
BEGIN {{ @tids[{pid}] = 1; }}

tracepoint:syscalls:sys_enter_* /pid == {pid}/ {{
    @tids[tid] = 1;
}}

tracepoint:sched:sched_switch /@tids[args.prev_pid]/ {{
    @off_start[args.prev_pid] = nsecs;
    @ctx_switches[args.prev_pid] = count();
}}

tracepoint:sched:sched_switch /@tids[args.next_pid] && @off_start[args.next_pid]/ {{
    $dur = (nsecs - @off_start[args.next_pid]) / 1000;
    @off_cpu[args.next_pid] = sum($dur);
    @wakeup_lat[args.next_pid] = avg($dur);
    delete(@off_start[args.next_pid]);
}}

interval:s:{int(duration)} {{
    print(@ctx_switches);
    print(@off_cpu);
    print(@wakeup_lat);
    exit();
}}
"""
        output = await self.run_script(script, duration + 2)
        return self._wrap(
            tool="ctrace_sched_summary", session_id=session.session_id, pid=pid,
            duration_s=duration, raw_output=output[:4000],
        )

    async def lock_contention(self, session_id: str | None, duration: float, threshold_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
tracepoint:syscalls:sys_enter_futex /pid == {pid}/ {{
    @lock_start[tid] = nsecs;
}}

tracepoint:syscalls:sys_exit_futex /pid == {pid} && @lock_start[tid]/ {{
    $dur = (nsecs - @lock_start[tid]) / 1000;
    delete(@lock_start[tid]);
    if ($dur >= {threshold_us}) {{
        printf("LOCK|%d|%d\\n", tid, $dur);
    }}
}}

interval:s:{int(duration)} {{ exit(); }}
"""
        output = await self.run_script(script, duration + 2)
        events = []
        for line in output.splitlines():
            if line.startswith("LOCK|"):
                parts = line.split("|")
                if len(parts) >= 3:
                    events.append({"tid": int(parts[1]), "wait_us": int(parts[2])})
        trace_events = [
            TraceEvent(
                ts_ns=None, category="lock", name="futex", phase="complete",
                tid=e["tid"], duration_us=e["wait_us"], status="ok",
            )
            for e in events[:500]
        ]
        return self._wrap(
            tool="ctrace_lock_contention", session_id=session.session_id, pid=pid,
            duration_s=duration, events=trace_events,
        )

    async def offcpu(self, session_id: str | None, duration: float, min_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
BEGIN {{ @tids[{pid}] = 1; }}

tracepoint:syscalls:sys_enter_* /pid == {pid}/ {{
    @tids[tid] = 1;
}}

tracepoint:sched:sched_switch /@tids[args.prev_pid]/ {{
    @off_start[args.prev_pid] = nsecs;
}}

tracepoint:sched:sched_switch /@tids[args.next_pid] && @off_start[args.next_pid]/ {{
    $dur = (nsecs - @off_start[args.next_pid]) / 1000;
    delete(@off_start[args.next_pid]);
    if ($dur >= {min_us}) {{
        @stacks[ustack()] = sum($dur);
    }}
}}

interval:s:{int(duration)} {{
    print(@stacks);
    exit();
}}
"""
        output = await self.run_script(script, duration + 2)
        caps = self._default_capabilities()
        caps["has_user_stacks"] = True
        return self._wrap(
            tool="ctrace_offcpu", session_id=session.session_id, pid=pid,
            duration_s=duration, capabilities=caps, raw_output=output[:8000],
        )

    async def tick_summary(self, session_id: str | None, tick_name: str, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined.")
        tick = session.ticks[tick_name]
        binary = session.binary_path or ""
        libc = self._get_libc()
        thread_pred = f' && comm == "{tick.thread_filter}"' if tick.thread_filter else ""
        script = f"""
uprobe:{binary}:{tick.function} /pid == {pid}{thread_pred}/ {{
    @tick_start[tid] = nsecs;
    @tick_sc[tid] = 0;
    @tick_alloc_n[tid] = 0;
}}

tracepoint:syscalls:sys_enter_* /pid == {pid} && @tick_start[tid]/ {{
    @tick_sc[tid]++;
}}

uprobe:{libc}:malloc /pid == {pid} && @tick_start[tid]/ {{
    @tick_alloc_n[tid]++;
}}

uretprobe:{binary}:{tick.function} /pid == {pid} && @tick_start[tid]/ {{
    $dur = (nsecs - @tick_start[tid]) / 1000;
    @durations = hist($dur);
    @count = count();
    @total = sum($dur);
    @min_d = min($dur);
    @max_d = max($dur);
    @avg_d = avg($dur);
    @avg_syscalls = avg(@tick_sc[tid]);
    @avg_allocs = avg(@tick_alloc_n[tid]);
    delete(@tick_start[tid]);
    delete(@tick_sc[tid]);
    delete(@tick_alloc_n[tid]);
}}

interval:s:{int(duration)} {{
    print(@count);
    print(@total);
    print(@min_d);
    print(@max_d);
    print(@avg_d);
    print(@avg_syscalls);
    print(@avg_allocs);
    print(@durations);
    exit();
}}
"""
        output = await self.run_script(script, duration + 2)
        stats: dict = {}
        for line in output.splitlines():
            for key, field in [
                ("@count:", "tick_count"), ("@total:", "total_us"),
                ("@min_d:", "min_us"), ("@max_d:", "max_us"), ("@avg_d:", "avg_us"),
                ("@avg_syscalls:", "avg_syscalls"), ("@avg_allocs:", "avg_allocs"),
            ]:
                if line.startswith(key):
                    try:
                        stats[field] = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
        return self._wrap(
            tool="ctrace_tick_summary", session_id=session.session_id, pid=pid,
            duration_s=duration,
            aggregates={"tick_stats": stats} if stats else None,
            raw_output=output[:4000],
        )

    async def tick_outliers(self, session_id: str | None, tick_name: str, duration: float, threshold_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined.")
        tick = session.ticks[tick_name]
        binary = session.binary_path or ""
        libc = self._get_libc()
        thread_pred = f' && comm == "{tick.thread_filter}"' if tick.thread_filter else ""
        script = f"""
uprobe:{binary}:{tick.function} /pid == {pid}{thread_pred}/ {{
    @tick_start[tid] = nsecs;
    @tick_sc[tid] = 0;
    @tick_alloc_n[tid] = 0;
    @tick_alloc_b[tid] = 0;
}}

tracepoint:syscalls:sys_enter_* /pid == {pid} && @tick_start[tid]/ {{
    @tick_sc[tid]++;
}}

uprobe:{libc}:malloc /pid == {pid} && @tick_start[tid]/ {{
    @tick_alloc_n[tid]++;
    @tick_alloc_b[tid] += arg0;
}}

uretprobe:{binary}:{tick.function} /pid == {pid} && @tick_start[tid]/ {{
    $dur = (nsecs - @tick_start[tid]) / 1000;
    @total_ticks = count();
    if ($dur >= {threshold_us}) {{
        printf("OUTLIER|%d|%d|%d|%d\\n", $dur, @tick_sc[tid], @tick_alloc_n[tid], @tick_alloc_b[tid]);
        @outlier_count = count();
    }}
    delete(@tick_start[tid]);
    delete(@tick_sc[tid]);
    delete(@tick_alloc_n[tid]);
    delete(@tick_alloc_b[tid]);
}}

interval:s:{int(duration)} {{
    print(@total_ticks);
    print(@outlier_count);
    exit();
}}
"""
        output = await self.run_script(script, duration + 2)
        outliers = []
        for line in output.splitlines():
            if line.startswith("OUTLIER|"):
                parts = line.split("|")
                if len(parts) >= 5:
                    outliers.append({
                        "duration_us": int(parts[1]),
                        "syscall_count": int(parts[2]),
                        "alloc_count": int(parts[3]),
                        "alloc_bytes": int(parts[4]),
                    })
        trace_events = [
            TraceEvent(
                ts_ns=None, category="tick", name=tick_name, phase="complete",
                duration_us=o["duration_us"], status="ok", labels=["outlier"],
                fields={"syscall_count": o["syscall_count"], "alloc_count": o["alloc_count"], "alloc_bytes": o["alloc_bytes"]},
            )
            for o in outliers[:200]
        ]
        return self._wrap(
            tool="ctrace_tick_outliers", session_id=session.session_id, pid=pid,
            duration_s=duration, events=trace_events,
        )

    async def tick_compare(self, session_id: str | None, tick_name: str, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined.")
        tick = session.ticks[tick_name]
        binary = session.binary_path or ""
        thread_pred = f' && comm == "{tick.thread_filter}"' if tick.thread_filter else ""
        script = f"""
uprobe:{binary}:{tick.function} /pid == {pid}{thread_pred}/ {{
    @tick_start[tid] = nsecs;
}}

uretprobe:{binary}:{tick.function} /pid == {pid} && @tick_start[tid]/ {{
    $dur = (nsecs - @tick_start[tid]) / 1000;
    printf("TICK|%d\\n", $dur);
    delete(@tick_start[tid]);
}}

interval:s:{int(duration)} {{ exit(); }}
"""
        output = await self.run_script(script, duration + 2)
        ticks = []
        for line in output.splitlines():
            if line.startswith("TICK|"):
                parts = line.split("|")
                if len(parts) >= 2:
                    ticks.append({"duration_us": int(parts[1])})

        if not ticks:
            return self._wrap(
                tool="ctrace_tick_compare", session_id=session.session_id, pid=pid,
                duration_s=duration, errors=["No ticks captured"],
            )

        ticks.sort(key=lambda t: t["duration_us"])
        n = len(ticks)
        p50_idx = n // 2
        p99_idx = min(int(n * 0.99), n - 1)

        fast = ticks[:p50_idx + 1]
        slow = ticks[p99_idx:]

        def avg_dur(group):
            return sum(t["duration_us"] for t in group) // max(len(group), 1)

        comparison = {
            "total_ticks": n,
            "p50_duration_us": ticks[p50_idx]["duration_us"],
            "p99_duration_us": ticks[p99_idx]["duration_us"],
            "fast_avg_us": avg_dur(fast),
            "slow_avg_us": avg_dur(slow),
        }
        return self._wrap(
            tool="ctrace_tick_compare", session_id=session.session_id, pid=pid,
            duration_s=duration, aggregates={"tick_comparison": comparison},
        )

    async def probe(self, session_id: str | None, script: str, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = script.replace("$target", str(pid))
        output = await self.run_script(script, duration + 2)
        return self._wrap(
            tool="ctrace_probe", session_id=session.session_id, pid=pid,
            duration_s=duration, raw_output=output[:8000],
        )

    async def snapshot(self, session_id: str | None, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        libc = self._get_libc()
        script = f"""
tracepoint:raw_syscalls:sys_enter /pid == {pid}/ {{
    @sc_count = count();
}}

uprobe:{libc}:malloc /pid == {pid}/ {{
    @alloc_count = count();
    @alloc_bytes = sum(arg0);
}}

tracepoint:sched:sched_switch /args.prev_pid == {pid}/ {{
    @off_start[tid] = nsecs;
}}

tracepoint:sched:sched_switch /args.next_pid == {pid} && @off_start[tid]/ {{
    @sched_delays = hist((nsecs - @off_start[tid]) / 1000);
    delete(@off_start[tid]);
}}

interval:s:{int(duration)} {{
    print(@sc_count);
    print(@alloc_count);
    print(@alloc_bytes);
    print(@sched_delays);
    exit();
}}
"""
        output = await self.run_script(script, duration + 2)
        return self._wrap(
            tool="ctrace_snapshot", session_id=session.session_id, pid=pid,
            duration_s=duration, raw_output=output[:6000],
        )
