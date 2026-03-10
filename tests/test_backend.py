"""Tests for backend module: Session, SessionManager, and script generation."""

import asyncio
import os
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from ctrace.backend import Session, SessionManager, TickDefinition, get_backend
from ctrace.bpftrace_backend import BpftraceBackend
from ctrace.dtrace_backend import DTraceBackend


def _attach(b, pid=None, binary="/bin/test"):
    """Create a session on the backend using the current process PID."""
    b.sessions.create(pid=pid or os.getpid(), binary_path=binary)


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


def _nm_mock(stdout, returncode=0):
    return MagicMock(returncode=returncode, stdout=stdout, stderr="")

def _cfilt_mock(stdout, returncode=0):
    return MagicMock(returncode=returncode, stdout=stdout, stderr="")


class TestSymbols:
    def _backend(self, binary="/bin/test"):
        b = BpftraceBackend()
        _attach(b, binary=binary)
        return b

    def test_returns_text_symbol_names(self):
        b = self._backend()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _nm_mock("0000000000001600 T control_loop_tick\n0000000000001700 T main\n"),
                _cfilt_mock("control_loop_tick\nmain\n"),
            ]
            result = b.symbols("s1", None)
        names = [s["mangled"] for s in result["symbols"]]
        assert "control_loop_tick" in names
        assert "main" in names
        assert result["symbol_count"] == 2

    def test_tick_candidate_flagged(self):
        b = self._backend()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _nm_mock("0000000000001600 T update_physics\n0000000000001700 T helper\n"),
                _cfilt_mock("update_physics\nhelper\n"),
            ]
            result = b.symbols("s1", None)
        tick_names = [s["mangled"] for s in result["tick_candidates"]]
        assert "update_physics" in tick_names
        assert "helper" not in tick_names

    def test_filter_by_name(self):
        b = self._backend()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _nm_mock("0000000000001600 T tick_physics\n0000000000001700 T main\n"),
                _cfilt_mock("tick_physics\nmain\n"),
            ]
            result = b.symbols("s1", "tick")
        names = [s["mangled"] for s in result["symbols"]]
        assert "tick_physics" in names
        assert "main" not in names

    def test_cxx_demangling(self):
        b = self._backend()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _nm_mock("0000000000001600 T _Z17control_loop_ticki\n"),
                _cfilt_mock("control_loop_tick(int)\n"),
            ]
            result = b.symbols("s1", None)
        sym = result["symbols"][0]
        assert sym["mangled"] == "_Z17control_loop_ticki"
        assert sym["demangled"] == "control_loop_tick(int)"

    def test_nm_failure_raises(self):
        b = self._backend()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _nm_mock("", returncode=1)
            with pytest.raises(RuntimeError, match="nm failed"):
                b.symbols("s1", None)

    def test_nm_not_found_raises(self):
        b = self._backend()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(RuntimeError, match="nm not found"):
                b.symbols("s1", None)

    def test_no_binary_raises(self):
        b = BpftraceBackend()
        _attach(b, binary=None)
        with pytest.raises(ValueError, match="No binary path"):
            b.symbols("s1", None)

    def test_cfilt_line_count_mismatch_falls_back_to_mangled(self):
        b = self._backend()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _nm_mock("0000000000001600 T sym_a\n0000000000001700 T sym_b\n"),
                _cfilt_mock("sym_a\n"),  # one fewer line — mismatch
            ]
            result = b.symbols("s1", None)
        names = [s["mangled"] for s in result["symbols"]]
        assert "sym_a" in names
        assert "sym_b" in names
        # No demangled field when fallback triggered
        assert all("demangled" not in s for s in result["symbols"])

    def test_skips_compiler_artifacts(self):
        b = self._backend()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _nm_mock(
                    "0000000000001600 T __stack_chk_fail\n"
                    "0000000000001700 T _GLOBAL__sub_I_main\n"
                    "0000000000001800 T my_func\n"
                ),
                _cfilt_mock("my_func\n"),
            ]
            result = b.symbols("s1", None)
        names = [s["mangled"] for s in result["symbols"]]
        assert "__stack_chk_fail" not in names
        assert "_GLOBAL__sub_I_main" not in names
        assert "my_func" in names

    def test_skips_non_text_symbols(self):
        b = self._backend()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _nm_mock(
                    "0000000000004010 D global_var\n"
                    "0000000000001600 T real_func\n"
                    "                 U external_dep\n"
                ),
                _cfilt_mock("real_func\n"),
            ]
            result = b.symbols("s1", None)
        names = [s["mangled"] for s in result["symbols"]]
        assert "global_var" not in names
        assert "external_dep" not in names
        assert "real_func" in names


class TestThreads:
    def test_returns_current_process_threads(self):
        b = BpftraceBackend()
        _attach(b)
        result = b.threads("s1")
        assert result["pid"] == os.getpid()
        assert result["thread_count"] >= 1
        assert all("tid" in t for t in result["threads"])
        assert all("user_time_s" in t for t in result["threads"])
        assert all("system_time_s" in t for t in result["threads"])

    def test_thread_name_read_from_proc(self, tmp_path):
        """Thread name is read from /proc/<pid>/task/<tid>/comm on Linux."""
        comm_file = tmp_path / "comm"
        comm_file.write_text("physics\n")

        mock_thread = MagicMock()
        mock_thread.id = 42
        mock_thread.user_time = 1.5
        mock_thread.system_time = 0.5

        b = BpftraceBackend()
        b.sessions.create(pid=12345)

        import ctrace.backend as backend_mod
        orig_path = backend_mod.Path

        def fake_path(p):
            if "comm" in str(p):
                return comm_file
            return orig_path(p)

        with patch("psutil.Process") as mock_proc, \
             patch.object(backend_mod, "Path", side_effect=fake_path):
            mock_proc.return_value.threads.return_value = [mock_thread]
            result = b.threads("s1")

        assert result["threads"][0]["name"] == "physics"
        assert result["threads"][0]["tid"] == 42

    def test_dead_process_raises(self):
        b = BpftraceBackend()
        b.sessions.create(pid=999999999)
        with pytest.raises(ValueError, match="Cannot access"):
            b.threads("s1")


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
