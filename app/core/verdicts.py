# app/core/verdicts.py
from typing import Dict

def compute_connectivity_verdict(evidence: Dict) -> Dict[str, str]:
    """
    Returns a dict for report.build_markdown_report():
      {
        "status": "Connected|Partial|Failed|Unknown",
        "reason_code": "TCP_OK|NO_SYNACK|SERVER_RST|ICMP_UNREACHABLE|MISSING_ACK|INCOMPLETE|UNKNOWN",
        "explanation": "human-readable one-liner"
      }
    """
    meta = evidence.get("meta", {})
    if meta.get("proto") != "tcp":
        return {
            "status": "Unknown",
            "reason_code": "UNKNOWN",
            "explanation": "TCP-only verdict implemented at this stage"
        }

    tcp  = evidence.get("tcp", {})
    icmp = evidence.get("icmp", {})

    syn        = bool(tcp.get("syn_seen"))
    synack     = bool(tcp.get("synack_seen"))
    ack        = bool(tcp.get("ack_seen"))
    server_rst = bool(tcp.get("server_rst"))
    fin_seen   = bool(tcp.get("fin_seen"))
    icmp_events = icmp.get("unreachables", [])

    # Hard fails first
    if icmp_events:
        return {
            "status": "Failed",
            "reason_code": "ICMP_UNREACHABLE",
            "explanation": "ICMP unreachable/time-exceeded observed from an intermediate device"
        }
    if syn and not synack:
        return {
            "status": "Failed",
            "reason_code": "NO_SYNACK",
            "explanation": "Client SYN seen but no SYN-ACK from server (filtered/dropped/no listener)"
        }
    if server_rst:
        return {
            "status": "Failed",
            "reason_code": "SERVER_RST",
            "explanation": "Server sent RST (refused/closed connection)"
        }

    # Success
    if syn and synack and ack:
        return {
            "status": "Connected",
            "reason_code": "TCP_OK",
            "explanation": "TCP 3-way handshake completed"
        }

    # Partial
    if syn and synack and not ack:
        return {
            "status": "Partial",
            "reason_code": "MISSING_ACK",
            "explanation": "SYN and SYN-ACK seen, but final ACK missing"
        }
    if fin_seen:
        return {
            "status": "Partial",
            "reason_code": "INCOMPLETE",
            "explanation": "FIN observed without clear full handshake"
        }

    return {
        "status": "Unknown",
        "reason_code": "UNKNOWN",
        "explanation": "Insufficient signals for a determination"
    }
