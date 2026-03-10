"""Tests for schema module: build_envelope and type definitions."""

import pytest
from unittest.mock import patch

from ctrace.schema import Capabilities, TraceEvent, build_envelope


class TestBuildEnvelope:
    def _caps(self) -> Capabilities:
        return Capabilities(
            has_user_stacks=False, has_kernel_stacks=False,
            has_args=True, has_retval=True, has_tid=False,
            timing_source="event",
        )

    def test_required_keys_present(self):
        result = build_envelope(
            backend="dtrace", session_id="s1", pid=1234, tool="ctrace_syscall_summary",
            duration_s=5.0, capabilities=self._caps(),
        )
        assert result["schema_version"] == "1.0"
        assert result["backend"] == "dtrace"
        assert result["session_id"] == "s1"
        assert result["pid"] == 1234
        assert result["tool"] == "ctrace_syscall_summary"
        assert result["window"]["duration_s"] == 5.0
        assert result["window"]["start_time_unix_ns"] is not None
        assert result["window"]["end_time_unix_ns"] is not None
        assert result["capabilities"] == self._caps()
        assert result["warnings"] == []
        assert result["errors"] == []

    def test_platform_darwin(self):
        with patch("ctrace.schema.platform.system", return_value="Darwin"):
            result = build_envelope(
                backend="dtrace", session_id="s1", pid=1, tool="t",
                duration_s=1.0, capabilities=self._caps(),
            )
            assert result["platform"] == "macos"

    def test_platform_linux(self):
        with patch("ctrace.schema.platform.system", return_value="Linux"):
            result = build_envelope(
                backend="bpftrace", session_id="s1", pid=1, tool="t",
                duration_s=1.0, capabilities=self._caps(),
            )
            assert result["platform"] == "linux"

    def test_events_omitted_when_none(self):
        result = build_envelope(
            backend="dtrace", session_id="s1", pid=1, tool="t",
            duration_s=1.0, capabilities=self._caps(),
        )
        assert "events" not in result

    def test_events_present_when_provided(self):
        events = [TraceEvent(category="syscall", name="read", phase="complete")]
        result = build_envelope(
            backend="dtrace", session_id="s1", pid=1, tool="t",
            duration_s=1.0, capabilities=self._caps(), events=events,
        )
        assert result["events"] == events

    def test_aggregates_omitted_when_none(self):
        result = build_envelope(
            backend="dtrace", session_id="s1", pid=1, tool="t",
            duration_s=1.0, capabilities=self._caps(),
        )
        assert "aggregates" not in result

    def test_aggregates_present_when_provided(self):
        agg = {"syscall_by_name": [{"key": "read", "value": 42}]}
        result = build_envelope(
            backend="dtrace", session_id="s1", pid=1, tool="t",
            duration_s=1.0, capabilities=self._caps(), aggregates=agg,
        )
        assert result["aggregates"] == agg

    def test_raw_output_omitted_when_none(self):
        result = build_envelope(
            backend="dtrace", session_id="s1", pid=1, tool="t",
            duration_s=1.0, capabilities=self._caps(),
        )
        assert "raw_output" not in result

    def test_raw_output_present_when_provided(self):
        result = build_envelope(
            backend="dtrace", session_id="s1", pid=1, tool="t",
            duration_s=1.0, capabilities=self._caps(), raw_output="some output",
        )
        assert result["raw_output"] == "some output"

    def test_warnings_and_errors(self):
        result = build_envelope(
            backend="dtrace", session_id="s1", pid=1, tool="t",
            duration_s=1.0, capabilities=self._caps(),
            warnings=["SIP enabled"], errors=["probe blocked"],
        )
        assert result["warnings"] == ["SIP enabled"]
        assert result["errors"] == ["probe blocked"]

    def test_window_timestamps_reasonable(self):
        result = build_envelope(
            backend="dtrace", session_id="s1", pid=1, tool="t",
            duration_s=2.0, capabilities=self._caps(),
        )
        w = result["window"]
        assert w["end_time_unix_ns"] > w["start_time_unix_ns"]
        diff_ns = w["end_time_unix_ns"] - w["start_time_unix_ns"]
        assert diff_ns == 2_000_000_000
