"""Tests for dtrace output parsing."""

import pytest
from ctrace.dtrace_backend import DTraceBackend


@pytest.fixture
def backend():
    return DTraceBackend()


class TestParseAggregation:
    def test_basic(self, backend):
        output = """
  read                                                              42
  write                                                             17
  close                                                              3
"""
        result = backend._parse_aggregation(output)
        assert len(result) == 3
        assert result[0] == {"key": "read", "value": 42}
        assert result[1] == {"key": "write", "value": 17}
        assert result[2] == {"key": "close", "value": 3}

    def test_ignores_dtrace_headers(self, backend):
        output = """dtrace: description 'syscall:::entry' matched 42 probes
CPU     ID                    FUNCTION:NAME
  read                                                              42
"""
        result = backend._parse_aggregation(output)
        assert len(result) == 1
        assert result[0]["key"] == "read"

    def test_empty(self, backend):
        assert backend._parse_aggregation("") == []


class TestParseDelimited:
    def test_basic(self, backend):
        output = """TRACE|read|3|1024|42|150
TRACE|write|4|512|512|80
"""
        result = backend._parse_delimited(output, ["marker", "syscall", "fd", "size", "ret", "lat"])
        assert len(result) == 2
        assert result[0]["syscall"] == "read"
        assert result[0]["lat"] == "150"

    def test_no_delimiter(self, backend):
        output = "no delimiters here\n"
        result = backend._parse_delimited(output, ["a", "b"])
        assert result == []


class TestParseQuantize:
    def test_basic(self, backend):
        output = """
  read
           value  ------------- Distribution ------------- count
               1 |                                         0
               2 |@@@@                                     4
               4 |@@@@@@@@                                 8
               8 |@@@@@@@@@@@@@@                           14
              16 |@@@@@@@@@@                               10
              32 |@@@@                                     4
              64 |                                         0
"""
        result = backend._parse_quantize(output)
        assert "read" in result
        assert len(result["read"]) > 0


class TestTickOutputParsing:
    def test_parse_tick_events(self, backend):
        output = """TICK|150|3|2
TICK|200|5|1
TICK|1500|12|8
"""
        ticks = []
        for line in output.splitlines():
            if line.startswith("TICK|"):
                parts = line.split("|")
                if len(parts) >= 4:
                    ticks.append({
                        "duration_us": int(parts[1]),
                        "syscalls": int(parts[2]),
                        "allocs": int(parts[3]),
                    })
        assert len(ticks) == 3
        assert ticks[0]["duration_us"] == 150
        assert ticks[2]["syscalls"] == 12

    def test_parse_outlier_events(self, backend):
        output = """OUTLIER|1500|12|8|4096
OUTLIER|2000|15|3|1024
some other line
"""
        outliers = []
        for line in output.splitlines():
            if line.startswith("OUTLIER|"):
                parts = line.split("|")
                if len(parts) >= 5:
                    outliers.append({
                        "duration_us": int(parts[1]),
                        "syscalls": int(parts[2]),
                        "allocs": int(parts[3]),
                        "alloc_bytes": int(parts[4]),
                    })
        assert len(outliers) == 2
        assert outliers[0]["duration_us"] == 1500
        assert outliers[1]["alloc_bytes"] == 1024


class TestIOOutputParsing:
    def test_parse_slow_io(self, backend):
        output = """SLOW_IO|read|3|1024|5000
SLOW_IO|write|4|512|3000
"""
        events = []
        for line in output.splitlines():
            if line.startswith("SLOW_IO|"):
                parts = line.split("|")
                if len(parts) >= 5:
                    events.append({
                        "syscall": parts[1],
                        "fd": int(parts[2]),
                        "bytes": int(parts[3]),
                        "latency_us": int(parts[4]),
                    })
        assert len(events) == 2
        assert events[0]["latency_us"] == 5000

    def test_parse_io_aggregation(self, backend):
        output = """IO|read|3|count=42
IO|read|3|bytes=102400
IO|read|3|avg_us=150
IO|write|4|count=10
"""
        io_data = {}
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

        assert len(io_data) == 2
        assert io_data["read:fd3"]["count"] == 42
        assert io_data["read:fd3"]["bytes"] == 102400


class TestSchedOutputParsing:
    def test_parse_sched_lines(self, backend):
        output = """ON_CPU|12345|500000
OFF_CPU|12345|200000
CTX_SW|12345|150
WAKEUP|12345|1333
"""
        threads = {}
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

        assert 12345 in threads
        t = threads[12345]
        assert t["on_cpu_us"] == 500000
        assert t["context_switches"] == 150


class TestLockOutputParsing:
    def test_parse_lock_events(self, backend):
        output = """LOCK|100|deadbeef|5000
LOCK|101|cafebabe|3000
"""
        events = []
        for line in output.splitlines():
            if line.startswith("LOCK|"):
                parts = line.split("|")
                if len(parts) >= 4:
                    events.append({
                        "tid": int(parts[1]),
                        "lock_addr": parts[2],
                        "wait_us": int(parts[3]),
                    })
        assert len(events) == 2
        assert events[0]["wait_us"] == 5000
