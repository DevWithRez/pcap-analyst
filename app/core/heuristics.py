"""
Connectivity decision tree.
Keep rules simple and transparent. Prefer clear reason codes engineers recognize.
"""
from __future__ import annotations
from typing import Dict, Any

REASONS = {
    "NO_SYNACK": "No SYN-ACK observed; likely server unreachable, filtered, or no listener.",
    "ICMP_UNREACHABLE": "ICMP unreachable/time-exceeded seen from a hop or host.",
    "SERVER_RST": "Server sent RST indicating closed port or active refusal.",
    "TLS_ALERT": "TLS alert observed shortly after handshake attempt.",
    "HTTP_ERROR": "HTTP responded with error status (4xx/5xx).",
    "CONNECTED": "Handshake completed; application exchange observed.",
}


def analyze_connectivity(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Return a small verdict dict: {status, reason_code, explanation}.
    Order matters: we check hard-fail signals first, then partials, then success.
    """
    tcp = evidence.get("tcp", {})
    icmp = evidence.get("icmp", {})
    tls = evidence.get("tls", {})
    http = evidence.get("http", {})

    # 1) Hard failures (most actionable)
    if icmp.get("unreachables"):
        return {"status": "Failed", "reason_code": "ICMP_UNREACHABLE", "explanation": REASONS["ICMP_UNREACHABLE"]}

    if tcp.get("server_rst") and not tcp.get("ack_seen"):
        return {"status": "Failed", "reason_code": "SERVER_RST", "explanation": REASONS["SERVER_RST"]}

    if tcp.get("syn_seen") and not tcp.get("synack_seen"):
        return {"status": "Failed", "reason_code": "NO_SYNACK", "explanation": REASONS["NO_SYNACK"]}

    # 2) Partial / degraded signals
    if tls.get("alert_seen"):
        return {"status": "Partial", "reason_code": "TLS_ALERT", "explanation": REASONS["TLS_ALERT"]}

    if any(code >= 400 for code in http.get("status_codes", [])):
        return {"status": "Partial", "reason_code": "HTTP_ERROR", "explanation": REASONS["HTTP_ERROR"]}

    # 3) Success
    if tcp.get("ack_seen"):
        return {"status": "Connected", "reason_code": "CONNECTED", "explanation": REASONS["CONNECTED"]}

    # 4) Unknown / insufficient signals
    return {"status": "Unknown", "reason_code": "UNKNOWN", "explanation": "Insufficient evidence."}
