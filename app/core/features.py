"""
Derived metrics from evidence.
Phase 1 keeps this tiny; we only expose a convenience flag that some UIs/tests may use.
"""
from __future__ import annotations

def handshake_completed(evidence) -> bool:
    """True if we observed SYN, SYN-ACK, and ACK in order (coarsely)."""
    tcp = evidence.get("tcp", {})
    return bool(tcp.get("syn_seen") and tcp.get("synack_seen") and tcp.get("ack_seen"))
