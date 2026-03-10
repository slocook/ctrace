"""Tests for MCP server tool definitions."""

import asyncio
import pytest

from ctrace.mcp_server import mcp


class TestMCPTools:
    def test_all_tools_registered(self):
        """Verify all 21 tools are registered."""
        tools = asyncio.run(mcp.list_tools())
        tool_names = [t.name for t in tools]
        expected = [
            "ctrace_attach",
            "ctrace_launch",
            "ctrace_sessions",
            "ctrace_kill_session",
            "ctrace_status",
            "ctrace_syscall_summary",
            "ctrace_syscall_trace",
            "ctrace_alloc_summary",
            "ctrace_alloc_hotspots",
            "ctrace_io_summary",
            "ctrace_io_latency",
            "ctrace_sched_summary",
            "ctrace_lock_contention",
            "ctrace_offcpu",
            "ctrace_define_tick",
            "ctrace_tick_summary",
            "ctrace_tick_outliers",
            "ctrace_tick_compare",
            "ctrace_list_ticks",
            "ctrace_probe",
            "ctrace_snapshot",
        ]
        for name in expected:
            assert name in tool_names, f"Missing tool: {name}"

    def test_tool_count(self):
        tools = asyncio.run(mcp.list_tools())
        assert len(tools) == 23

    def test_new_tools_registered(self):
        tools = asyncio.run(mcp.list_tools())
        tool_names = [t.name for t in tools]
        assert "ctrace_symbols" in tool_names
        assert "ctrace_threads" in tool_names
