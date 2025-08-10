"""
Placeholder for richer per-connection state machines.
Phase 1 already emits a coarse timeline from parse.py; we expose a thin wrapper here
so the call sites won't change when we later implement detailed state tracking.
"""
from __future__ import annotations

def build_tcp_timeline(evidence):
    """Return chronological events as-is for now."""
    return evidence.get("timeline", [])
