"""Linux bpftrace backend."""

from __future__ import annotations

import re
import subprocess
from typing import Any

from ctrace.backend import Backend


class BpftraceBackend(Backend):

    def __init__(self) -> None:
        super().__init__()
        self._libc_path: str | None = None

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
                if "libc.so.6" in line and "x86_64" in line:
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
tracepoint:raw_syscalls:sys_enter /pid == {pid}/ {{
    @start[tid] = nsecs;
    @counts[ksym(*(kaddr("sys_call_table") + args.id * 8))] = count();
}}

tracepoint:raw_syscalls:sys_exit /pid == {pid} && @start[tid]/ {{
    $dur = (nsecs - @start[tid]) / 1000;
    @latency[ksym(*(kaddr("sys_call_table") + args.id * 8))] = sum($dur);
    delete(@start[tid]);
}}

interval:s:{int(duration)} {{
    print(@counts, {top_n});
    print(@latency, {top_n});
    exit();
}}
"""
        output = await self.run_script(script, duration + 2)
        return {
            "pid": pid,
            "duration_s": duration,
            "raw_output": output[:4000],
        }

    async def syscall_trace(self, session_id: str | None, duration: float, syscalls: list[str] | None, min_latency_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
tracepoint:raw_syscalls:sys_enter /pid == {pid}/ {{
    @start[tid] = nsecs;
}}

tracepoint:raw_syscalls:sys_exit /pid == {pid} && @start[tid]/ {{
    $dur = (nsecs - @start[tid]) / 1000;
    delete(@start[tid]);
    if ($dur >= {min_latency_us}) {{
        printf("TRACE|%s|%d|%d\\n", probe, args.id, $dur);
    }}
}}

interval:s:{int(duration)} {{ exit(); }}
"""
        output = await self.run_script(script, duration + 2)
        events = []
        for line in output.splitlines():
            if line.startswith("TRACE|"):
                parts = line.split("|")
                if len(parts) >= 4:
                    events.append({
                        "probe": parts[1],
                        "syscall_nr": parts[2],
                        "latency_us": int(parts[3]),
                    })
        return {
            "pid": pid,
            "duration_s": duration,
            "min_latency_us": min_latency_us,
            "events": events[:500],
            "total_captured": len(events),
        }

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
        return {
            "pid": pid,
            "duration_s": duration,
            "raw_output": output[:4000],
        }

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
        return {
            "pid": pid,
            "duration_s": duration,
            "raw_output": output[:8000],
        }

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
        return {
            "pid": pid,
            "duration_s": duration,
            "io_events": io_data[:500],
        }

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
        return {
            "pid": pid,
            "duration_s": duration,
            "threshold_us": threshold_us,
            "slow_ops": events[:500],
        }

    async def sched_summary(self, session_id: str | None, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
tracepoint:sched:sched_switch /args.prev_pid == {pid}/ {{
    @off_start[args.prev_pid, tid] = nsecs;
    @ctx_switches[tid] = count();
}}

tracepoint:sched:sched_switch /args.next_pid == {pid} && @off_start[{pid}, tid]/ {{
    $dur = (nsecs - @off_start[{pid}, tid]) / 1000;
    @off_cpu[tid] = sum($dur);
    @wakeup_lat[tid] = avg($dur);
    delete(@off_start[{pid}, tid]);
}}

interval:s:{int(duration)} {{
    print(@ctx_switches);
    print(@off_cpu);
    print(@wakeup_lat);
    exit();
}}
"""
        output = await self.run_script(script, duration + 2)
        return {
            "pid": pid,
            "duration_s": duration,
            "raw_output": output[:4000],
        }

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
        return {
            "pid": pid,
            "duration_s": duration,
            "threshold_us": threshold_us,
            "contention_events": events[:500],
        }

    async def offcpu(self, session_id: str | None, duration: float, min_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = f"""
tracepoint:sched:sched_switch /args.prev_pid == {pid}/ {{
    @off_start[tid] = nsecs;
}}

tracepoint:sched:sched_switch /args.next_pid == {pid} && @off_start[tid]/ {{
    $dur = (nsecs - @off_start[tid]) / 1000;
    delete(@off_start[tid]);
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
        return {
            "pid": pid,
            "duration_s": duration,
            "min_us": min_us,
            "raw_output": output[:8000],
        }

    async def tick_summary(self, session_id: str | None, tick_name: str, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined.")
        tick = session.ticks[tick_name]
        binary = session.binary_path or ""
        script = f"""
uprobe:{binary}:{tick.function} /pid == {pid}/ {{
    @tick_start[tid] = nsecs;
}}

uretprobe:{binary}:{tick.function} /pid == {pid} && @tick_start[tid]/ {{
    $dur = (nsecs - @tick_start[tid]) / 1000;
    @durations = hist($dur);
    @count = count();
    @total = sum($dur);
    @min_d = min($dur);
    @max_d = max($dur);
    @avg_d = avg($dur);
    delete(@tick_start[tid]);
}}

interval:s:{int(duration)} {{
    print(@count);
    print(@total);
    print(@min_d);
    print(@max_d);
    print(@avg_d);
    print(@durations);
    exit();
}}
"""
        output = await self.run_script(script, duration + 2)
        return {
            "pid": pid,
            "tick": tick_name,
            "function": tick.function,
            "duration_s": duration,
            "raw_output": output[:4000],
        }

    async def tick_outliers(self, session_id: str | None, tick_name: str, duration: float, threshold_us: int) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined.")
        tick = session.ticks[tick_name]
        binary = session.binary_path or ""
        script = f"""
uprobe:{binary}:{tick.function} /pid == {pid}/ {{
    @tick_start[tid] = nsecs;
}}

uretprobe:{binary}:{tick.function} /pid == {pid} && @tick_start[tid]/ {{
    $dur = (nsecs - @tick_start[tid]) / 1000;
    delete(@tick_start[tid]);
    @total_ticks = count();
    if ($dur >= {threshold_us}) {{
        printf("OUTLIER|%d\\n", $dur);
        @outlier_count = count();
    }}
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
                if len(parts) >= 2:
                    outliers.append({"duration_us": int(parts[1])})
        return {
            "pid": pid,
            "tick": tick_name,
            "threshold_us": threshold_us,
            "duration_s": duration,
            "outliers": outliers[:200],
        }

    async def tick_compare(self, session_id: str | None, tick_name: str, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        if tick_name not in session.ticks:
            raise ValueError(f"Tick '{tick_name}' not defined.")
        tick = session.ticks[tick_name]
        binary = session.binary_path or ""
        script = f"""
uprobe:{binary}:{tick.function} /pid == {pid}/ {{
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
            return {"pid": pid, "tick": tick_name, "error": "No ticks captured"}

        ticks.sort(key=lambda t: t["duration_us"])
        n = len(ticks)
        p50_idx = n // 2
        p99_idx = min(int(n * 0.99), n - 1)

        fast = ticks[:p50_idx + 1]
        slow = ticks[p99_idx:]

        def avg_dur(group):
            return sum(t["duration_us"] for t in group) // max(len(group), 1)

        return {
            "pid": pid,
            "tick": tick_name,
            "total_ticks": n,
            "p50_duration_us": ticks[p50_idx]["duration_us"],
            "p99_duration_us": ticks[p99_idx]["duration_us"],
            "fast_avg_us": avg_dur(fast),
            "slow_avg_us": avg_dur(slow),
        }

    async def probe(self, session_id: str | None, script: str, duration: float) -> dict:
        session = self.sessions.get_default(session_id)
        pid = session.pid
        script = script.replace("$target", str(pid))
        output = await self.run_script(script, duration + 2)
        return {"pid": pid, "duration_s": duration, "output": output[:8000]}

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
        status = session.status_info()
        return {
            "pid": pid,
            "duration_s": duration,
            "process_status": status,
            "ticks_defined": list(session.ticks.keys()),
            "raw_output": output[:6000],
        }
