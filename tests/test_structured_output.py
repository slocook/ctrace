"""Tests for structured output envelopes from backends."""

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, patch, PropertyMock

from ctrace.dtrace_backend import DTraceBackend
from ctrace.bpftrace_backend import BpftraceBackend


ENVELOPE_KEYS = {"schema_version", "backend", "platform", "session_id", "pid", "tool", "window", "capabilities", "warnings", "errors"}


def _make_dtrace_backend(sip: bool = False) -> DTraceBackend:
    b = DTraceBackend()
    b._sip_enabled = sip
    return b


def _attach(backend, pid=None):
    """Attach to current process for testing."""
    if pid is None:
        pid = os.getpid()
    return asyncio.run(backend.attach(pid))


class TestDTraceEnvelopeKeys:
    """Verify all dtrace tool returns include envelope metadata."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_syscall_summary_sip(self):
        b = _make_dtrace_backend(sip=True)
        _attach(b)
        with patch.object(b, "_run_fs_usage", new_callable=AsyncMock, return_value=""):
            result = self._run(b.syscall_summary(None, 1.0, 10))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert result["schema_version"] == "1.0"
        assert result["backend"] == "dtrace"
        assert result["tool"] == "ctrace_syscall_summary"
        # Legacy keys preserved
        assert "pid" in result
        assert "duration_s" in result["window"]

    def test_syscall_summary_no_sip(self):
        b = _make_dtrace_backend(sip=False)
        _attach(b)
        with patch.object(b, "_run_inline", new_callable=AsyncMock, return_value="  read  42\n  write  17\n"):
            result = self._run(b.syscall_summary(None, 1.0, 10))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert result["tool"] == "ctrace_syscall_summary"
        assert "aggregates" in result
        assert "syscall_by_name" in result["aggregates"]

    def test_syscall_trace_sip(self):
        b = _make_dtrace_backend(sip=True)
        _attach(b)
        with patch.object(b, "_run_fs_usage", new_callable=AsyncMock, return_value=""):
            result = self._run(b.syscall_trace(None, 1.0, None, 0))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert result["tool"] == "ctrace_syscall_trace"

    def test_alloc_summary_sip(self):
        b = _make_dtrace_backend(sip=True)
        _attach(b)
        with patch.object(b, "_run_inline", new_callable=AsyncMock, return_value="alloc_regions 5\n"):
            result = self._run(b.alloc_summary(None, 1.0))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert "aggregates" in result
        assert "alloc_stats" in result["aggregates"]

    def test_alloc_hotspots_sip_error(self):
        b = _make_dtrace_backend(sip=True)
        _attach(b)
        result = self._run(b.alloc_hotspots(None, 1.0, 10))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert len(result["errors"]) > 0

    def test_sched_summary_sip_error(self):
        b = _make_dtrace_backend(sip=True)
        _attach(b)
        result = self._run(b.sched_summary(None, 1.0))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert len(result["errors"]) > 0

    def test_io_summary_sip(self):
        b = _make_dtrace_backend(sip=True)
        _attach(b)
        with patch.object(b, "_run_fs_usage", new_callable=AsyncMock, return_value=""):
            result = self._run(b.io_summary(None, 1.0))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert result["capabilities"]["timing_source"] == "event"

    def test_probe_no_sip(self):
        b = _make_dtrace_backend(sip=False)
        _attach(b)
        with patch.object(b, "_run_inline", new_callable=AsyncMock, return_value="hello"):
            result = self._run(b.probe(None, "BEGIN { printf(\"hello\"); }", 1.0))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert result["tool"] == "ctrace_probe"
        assert result["raw_output"] == "hello"

    def test_snapshot_sip(self):
        b = _make_dtrace_backend(sip=True)
        _attach(b)
        with patch.object(b, "_run_fs_usage", new_callable=AsyncMock, return_value=""), \
             patch.object(b, "_run_inline", new_callable=AsyncMock, return_value=""):
            result = self._run(b.snapshot(None, 1.0))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert result["tool"] == "ctrace_snapshot"


class TestBpftraceEnvelopeKeys:
    """Verify bpftrace tool returns include envelope metadata."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_syscall_summary(self):
        b = BpftraceBackend()
        _attach(b)
        with patch.object(b, "run_script", new_callable=AsyncMock, return_value="@counts[read]: 42\n"):
            result = self._run(b.syscall_summary(None, 1.0, 10))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert result["backend"] == "bpftrace"
        assert result["tool"] == "ctrace_syscall_summary"

    def test_io_latency(self):
        b = BpftraceBackend()
        _attach(b)
        output = "SLOW_IO|sys_exit_read|3|1024|5000\n"
        with patch.object(b, "run_script", new_callable=AsyncMock, return_value=output):
            result = self._run(b.io_latency(None, 1.0, 1000))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert result["tool"] == "ctrace_io_latency"
        assert len(result["events"]) == 1
        assert result["events"][0]["category"] == "io"
        assert result["events"][0]["duration_us"] == 5000

    def test_lock_contention(self):
        b = BpftraceBackend()
        _attach(b)
        output = "LOCK|100|5000\n"
        with patch.object(b, "run_script", new_callable=AsyncMock, return_value=output):
            result = self._run(b.lock_contention(None, 1.0, 100))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert result["events"][0]["category"] == "lock"
        assert result["events"][0]["tid"] == 100

    def test_tick_compare_no_ticks(self):
        b = BpftraceBackend()
        _attach(b)
        session = b.sessions.get_default(None)
        from ctrace.backend import TickDefinition
        session.ticks["test"] = TickDefinition(name="test", function="test_func")
        with patch.object(b, "run_script", new_callable=AsyncMock, return_value=""):
            result = self._run(b.tick_compare(None, "test", 1.0))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert result["errors"] == ["No ticks captured"]

    def test_snapshot(self):
        b = BpftraceBackend()
        _attach(b)
        with patch.object(b, "run_script", new_callable=AsyncMock, return_value="@sc_count: 100\n"):
            result = self._run(b.snapshot(None, 1.0))
        assert ENVELOPE_KEYS.issubset(result.keys())
        assert result["tool"] == "ctrace_snapshot"


class TestCrossBackendConsistency:
    """Same tool on dtrace vs bpftrace returns identical top-level envelope keys."""

    def test_syscall_summary_same_keys(self):
        dt = _make_dtrace_backend(sip=True)
        bp = BpftraceBackend()
        _attach(dt)
        _attach(bp)

        with patch.object(dt, "_run_fs_usage", new_callable=AsyncMock, return_value=""):
            dt_result = asyncio.run(dt.syscall_summary(None, 1.0, 10))
        with patch.object(bp, "run_script", new_callable=AsyncMock, return_value=""):
            bp_result = asyncio.run(bp.syscall_summary(None, 1.0, 10))

        dt_envelope = ENVELOPE_KEYS & set(dt_result.keys())
        bp_envelope = ENVELOPE_KEYS & set(bp_result.keys())
        assert dt_envelope == ENVELOPE_KEYS
        assert bp_envelope == ENVELOPE_KEYS

    def test_capabilities_structure_identical(self):
        dt = _make_dtrace_backend(sip=False)
        bp = BpftraceBackend()
        _attach(dt)
        _attach(bp)

        with patch.object(dt, "_run_inline", new_callable=AsyncMock, return_value=""):
            dt_result = asyncio.run(dt.syscall_summary(None, 1.0, 10))
        with patch.object(bp, "run_script", new_callable=AsyncMock, return_value=""):
            bp_result = asyncio.run(bp.syscall_summary(None, 1.0, 10))

        dt_cap_keys = set(dt_result["capabilities"].keys())
        bp_cap_keys = set(bp_result["capabilities"].keys())
        assert dt_cap_keys == bp_cap_keys
