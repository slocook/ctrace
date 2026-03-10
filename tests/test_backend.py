"""Tests for backend module: Session, SessionManager, and script generation."""

import asyncio
import os
import pytest
from unittest.mock import patch, AsyncMock

from ctrace.backend import Session, SessionManager, TickDefinition, get_backend
from ctrace.bpftrace_backend import BpftraceBackend
from ctrace.dtrace_backend import DTraceBackend


def _attach(b, pid=None):
    """Create a session on the backend using the current process PID."""
    b.sessions.create(pid=pid or os.getpid(), binary_path="/bin/test")


class TestSession:
    def test_is_alive_current_pid(self):
        s = Session(session_id="s1", pid=os.getpid())
        assert s.is_alive()

    def test_is_alive_bogus_pid(self):
        s = Session(session_id="s1", pid=999999999)
        assert not s.is_alive()

    def test_status_info_current_pid(self):
        s = Session(session_id="s1", pid=os.getpid())
        info = s.status_info()
        assert info["alive"]
        assert info["pid"] == os.getpid()
        assert "memory_rss_mb" in info
        assert "num_threads" in info

    def test_status_info_dead_pid(self):
        s = Session(session_id="s1", pid=999999999)
        info = s.status_info()
        assert not info["alive"]


class TestSessionManager:
    def test_create_and_get(self):
        sm = SessionManager()
        s = sm.create(pid=os.getpid())
        assert s.session_id == "s1"
        assert sm.get("s1") is s

    def test_get_nonexistent(self):
        sm = SessionManager()
        with pytest.raises(ValueError, match="No session"):
            sm.get("s99")

    def test_get_default_single(self):
        sm = SessionManager()
        s = sm.create(pid=os.getpid())
        assert sm.get_default(None) is s

    def test_get_default_explicit(self):
        sm = SessionManager()
        s1 = sm.create(pid=os.getpid())
        s2 = sm.create(pid=os.getpid())
        assert sm.get_default("s1") is s1
        assert sm.get_default("s2") is s2

    def test_get_default_multiple_no_id(self):
        sm = SessionManager()
        sm.create(pid=os.getpid())
        sm.create(pid=os.getpid())
        with pytest.raises(ValueError, match="Multiple sessions"):
            sm.get_default(None)

    def test_get_default_empty(self):
        sm = SessionManager()
        with pytest.raises(ValueError, match="No active sessions"):
            sm.get_default(None)

    def test_remove(self):
        sm = SessionManager()
        s = sm.create(pid=os.getpid())
        sm.remove(s.session_id)
        with pytest.raises(ValueError):
            sm.get(s.session_id)

    def test_list_all(self):
        sm = SessionManager()
        sm.create(pid=os.getpid(), binary_path="/usr/bin/test")
        result = sm.list_all()
        assert len(result) == 1
        assert result[0]["pid"] == os.getpid()
        assert result[0]["binary_path"] == "/usr/bin/test"
        assert result[0]["alive"]


class TestTickDefinition:
    def test_basic(self):
        td = TickDefinition(name="physics", function="physics_update")
        assert td.name == "physics"
        assert td.function == "physics_update"
        assert td.thread_filter is None

    def test_with_filter(self):
        td = TickDefinition(name="render", function="render_frame", thread_filter="RenderThread")
        assert td.thread_filter == "RenderThread"


class TestThreadFilterValidation:
    """define_tick must reject thread_filter values that could inject into tracer scripts."""

    def _backend(self):
        b = BpftraceBackend()
        _attach(b)
        return b

    @pytest.mark.parametrize("name", [
        "physics",
        "RenderThread",
        "audio-io",
        "worker_1",
        "Worker 3",
        "net.recv",
        "A" * 64,
    ])
    def test_valid_thread_filters(self, name):
        b = self._backend()
        result = b.define_tick("s1", "tick", "fn", thread_filter=name)
        assert result["defined"] == "tick"

    @pytest.mark.parametrize("bad", [
        'physics"',          # breaks string literal in both backends
        'thread" || 1 == 1', # predicate injection
        '/etc/passwd',       # dtrace predicate delimiter
        'a/b',               # dtrace predicate delimiter
        'thread\x00name',    # null byte
        '',                  # empty string
        'A' * 65,            # too long
        'thread\nname',      # newline
    ])
    def test_invalid_thread_filters_rejected(self, bad):
        b = self._backend()
        with pytest.raises(ValueError, match="thread_filter"):
            b.define_tick("s1", "tick", "fn", thread_filter=bad)

    def test_none_filter_accepted(self):
        b = self._backend()
        result = b.define_tick("s1", "tick", "fn", thread_filter=None)
        assert result["defined"] == "tick"


class TestThreadFilterScriptGeneration:
    """Verify thread_filter appears correctly in generated tracer scripts."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_bpftrace_tick_summary_with_filter(self):
        b = BpftraceBackend()
        _attach(b)
        b.define_tick("s1", "tick", "my_func", thread_filter="PhysicsThread")
        captured = []
        async def capture(script, *a, **kw):
            captured.append(script)
            return ""
        with patch.object(b, "run_script", side_effect=capture):
            self._run(b.tick_summary("s1", "tick", 1.0))
        assert 'comm == "PhysicsThread"' in captured[0]

    def test_bpftrace_tick_summary_without_filter(self):
        b = BpftraceBackend()
        _attach(b)
        b.define_tick("s1", "tick", "my_func", thread_filter=None)
        captured = []
        async def capture(script, *a, **kw):
            captured.append(script)
            return ""
        with patch.object(b, "run_script", side_effect=capture):
            self._run(b.tick_summary("s1", "tick", 1.0))
        assert "comm ==" not in captured[0]

    def test_bpftrace_tick_outliers_with_filter(self):
        b = BpftraceBackend()
        _attach(b)
        b.define_tick("s1", "tick", "my_func", thread_filter="AudioThread")
        captured = []
        async def capture(script, *a, **kw):
            captured.append(script)
            return ""
        with patch.object(b, "run_script", side_effect=capture):
            self._run(b.tick_outliers("s1", "tick", 1.0, 1000))
        assert 'comm == "AudioThread"' in captured[0]

    def test_bpftrace_tick_compare_with_filter(self):
        b = BpftraceBackend()
        _attach(b)
        b.define_tick("s1", "tick", "my_func", thread_filter="RenderThread")
        captured = []
        async def capture(script, *a, **kw):
            captured.append(script)
            return ""
        with patch.object(b, "run_script", side_effect=capture):
            self._run(b.tick_compare("s1", "tick", 1.0))
        assert 'comm == "RenderThread"' in captured[0]

    def test_dtrace_tick_summary_with_filter(self):
        b = DTraceBackend()
        b._sip_enabled = False
        _attach(b)
        b.define_tick("s1", "tick", "my_func", thread_filter="PhysicsThread")
        captured = []
        async def capture(script, *a, **kw):
            captured.append(script)
            return ""
        with patch.object(b, "_run_inline", side_effect=capture):
            self._run(b.tick_summary("s1", "tick", 1.0))
        assert 'curthread->t_name == "PhysicsThread"' in captured[0]

    def test_dtrace_tick_outliers_with_filter(self):
        b = DTraceBackend()
        b._sip_enabled = False
        _attach(b)
        b.define_tick("s1", "tick", "my_func", thread_filter="AudioThread")
        captured = []
        async def capture(script, *a, **kw):
            captured.append(script)
            return ""
        with patch.object(b, "_run_inline", side_effect=capture):
            self._run(b.tick_outliers("s1", "tick", 1.0, 1000))
        assert 'curthread->t_name == "AudioThread"' in captured[0]

    def test_dtrace_tick_compare_with_filter(self):
        b = DTraceBackend()
        b._sip_enabled = False
        _attach(b)
        b.define_tick("s1", "tick", "my_func", thread_filter="RenderThread")
        captured = []
        async def capture(script, *a, **kw):
            captured.append(script)
            return ""
        with patch.object(b, "_run_inline", side_effect=capture):
            self._run(b.tick_compare("s1", "tick", 1.0))
        assert 'curthread->t_name == "RenderThread"' in captured[0]


class TestGetBackend:
    def test_darwin(self):
        with patch("platform.system", return_value="Darwin"):
            with patch.dict(os.environ, {}, clear=True):
                backend = get_backend()
                from ctrace.dtrace_backend import DTraceBackend
                assert isinstance(backend, DTraceBackend)

    def test_linux(self):
        with patch("platform.system", return_value="Linux"):
            with patch.dict(os.environ, {}, clear=True):
                backend = get_backend()
                from ctrace.bpftrace_backend import BpftraceBackend
                assert isinstance(backend, BpftraceBackend)

    def test_env_override_dtrace(self):
        with patch.dict(os.environ, {"CTRACE_BACKEND": "dtrace"}):
            backend = get_backend()
            from ctrace.dtrace_backend import DTraceBackend
            assert isinstance(backend, DTraceBackend)

    def test_env_override_bpftrace(self):
        with patch.dict(os.environ, {"CTRACE_BACKEND": "bpftrace"}):
            backend = get_backend()
            from ctrace.bpftrace_backend import BpftraceBackend
            assert isinstance(backend, BpftraceBackend)

    def test_unsupported_platform(self):
        with patch("platform.system", return_value="Windows"):
            with patch.dict(os.environ, {}, clear=True):
                with pytest.raises(RuntimeError, match="Unsupported platform"):
                    get_backend()
