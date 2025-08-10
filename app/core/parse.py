"""
PCAP parsing using Scapy.

What this does:
- Filters packets to just the src/dst pair (either direction)
- Applies optional port/proto filters
- Emits a compact "evidence" dict with TCP/ICMP/TLS/HTTP signals + a simple timeline

Why Scapy? It's pure Python and works well on Raspberry Pi. We'll add optional PyShark later.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, Optional

from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.packet import Raw

# Lightweight TLS/HTTP heuristics to keep deps small
TLS_RECORD_HANDSHAKE = 0x16  # TLS handshake record
TLS_RECORD_ALERT = 0x15      # TLS alert record
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
HTTP_RESP_PREFIX = b"HTTP/1."


def _is_tls_record(payload: bytes, record_type: int) -> bool:
    """True if bytes look like a TLS record of the given type (first byte),
    and the version major is 0x03 (TLS/SSL)."""
    return len(payload) >= 3 and payload[0] == record_type and payload[1] == 0x03


def _is_http_request(payload: bytes) -> bool:
    """True if bytes start with a common HTTP method."""
    return any(payload.startswith(m) for m in HTTP_METHODS)


def _is_http_response(payload: bytes) -> bool:
    """True if bytes start with an HTTP/1.x status line."""
    return payload.startswith(HTTP_RESP_PREFIX)


def _direction(src: str, dst: str, pkt_src: str, pkt_dst: str) -> str:
    """Human-friendly direction tag for timeline entries."""
    return "client->server" if (pkt_src == src and pkt_dst == dst) else "server->client"


def parse_pcap_for_pair(
    pcap_path: Path,
    src: str,
    dst: str,
    sport: Optional[int] = None,
    dport: Optional[int] = None,
    proto: str = "tcp",
) -> Dict[str, Any]:
    """Scan the PCAP and extract compact, explainable signals for a src↔dst pair.

    Output: a stable "evidence" dict used by heuristics/report.
    We keep it intentionally small: booleans, tiny lists, and a timeline.
    """
    evidence: Dict[str, Any] = {
        "meta": {"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto},
        "tcp": {
            "syn_seen": False,
            "synack_seen": False,
            "ack_seen": False,
            "client_retx": 0,
            "server_retx": 0,
            "server_rst": False,
            "fin_seen": False,
        },
        "icmp": {"unreachables": []},
        "arp": {"queries": 0, "replies": 0},
        "tls": {"client_hello": False, "server_hello": False, "alert_seen": False},
        "http": {"requests": [], "status_codes": []},
        "timeline": [],
    }

    count = 0
    with PcapReader(str(pcap_path)) as pr:
        for pkt in pr:
            count += 1

            # Capture ARP even without IP header (L2 resolution context)
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                if arp.pdst == dst or arp.psrc == dst:
                    evidence["arp"]["queries"] += int(arp.op == 1)
                    evidence["arp"]["replies"] += int(arp.op == 2)
                    evidence["timeline"].append({
                        "ts": float(pkt.time),
                        "event": "ARP",
                        "detail": f"op={arp.op} who-has {arp.pdst} tell {arp.psrc}",
                    })

            # Only analyze L3/L4 for IP packets
            if not pkt.haslayer(IP):
                continue

            ip = pkt[IP]
            pkt_src, pkt_dst = ip.src, ip.dst

            # NEW: capture ICMP errors from intermediate hops if addressed to our endpoints
            if pkt.haslayer(ICMP) and pkt_dst in (src, dst):
                icmp = pkt[ICMP]
                if icmp.type in (3, 11):  # 3=dest unreachable, 11=time exceeded
                    evidence["icmp"]["unreachables"].append({
                        "ts": float(pkt.time),
                        "type": int(icmp.type),
                        "code": int(icmp.code),
                        "from": pkt_src,  # device that sent the error (router/firewall/host)
                    })

            # For the rest of analysis, restrict to the src/dst pair (either direction)
            if not ((pkt_src == src and pkt_dst == dst) or (pkt_src == dst and pkt_dst == src)):
                continue

            # Protocol filter
            if proto == "tcp" and not pkt.haslayer(TCP):
                continue
            if proto == "udp" and not pkt.haslayer(UDP):
                continue
            if proto == "icmp" and not pkt.haslayer(ICMP):
                continue

            # Optional port filters (ignored for ICMP)
            ps = pd = None
            if pkt.haslayer(TCP):
                l4 = pkt[TCP]
                ps, pd = l4.sport, l4.dport
            elif pkt.haslayer(UDP):
                l4 = pkt[UDP]
                ps, pd = l4.sport, l4.dport

            if sport is not None and ps is not None and ps != sport and pd != sport:
                # allow either direction to match the given source port
                continue
            if dport is not None and pd is not None and ps != dport and pd != dport:
                continue

            direction = _direction(src, dst, pkt_src, pkt_dst)

            # ---- TCP signals ----
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                flags = tcp.flags

                # SYN (client initiating connection)
                if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
                    evidence["tcp"]["syn_seen"] = True
                    evidence["timeline"].append({"ts": float(pkt.time), "event": "TCP", "detail": f"{direction} SYN"})

                # SYN-ACK (server reply)
                if (flags & 0x12) == 0x12:  # SYN + ACK
                    evidence["tcp"]["synack_seen"] = True
                    evidence["timeline"].append({"ts": float(pkt.time), "event": "TCP", "detail": f"{direction} SYN-ACK"})

                # Final ACK of 3-way handshake (only mark after we saw SYN-ACK)
                if (flags & 0x10) and not (flags & 0x02) and evidence["tcp"]["synack_seen"]:
                    evidence["tcp"]["ack_seen"] = True

                # RST (server refused/closed)
                if flags & 0x04:
                    if direction == "server->client":
                        evidence["tcp"]["server_rst"] = True
                    evidence["timeline"].append({"ts": float(pkt.time), "event": "TCP", "detail": f"{direction} RST"})

                # FIN (either side closed)
                if flags & 0x01:
                    evidence["tcp"]["fin_seen"] = True

                # Coarse retransmission heuristic: repeated SYNs -> bump a counter
                if flags & 0x02 and hasattr(tcp, "seq"):
                    if direction == "client->server":
                        evidence["tcp"]["client_retx"] += 1
                    else:
                        evidence["tcp"]["server_retx"] += 1

                # Lightweight TLS/HTTP hints
                if Raw in pkt:
                    payload: bytes = bytes(pkt[Raw].load)
                    # TLS records
                    if _is_tls_record(payload, TLS_RECORD_HANDSHAKE):
                        if direction == "client->server":
                            evidence["tls"]["client_hello"] = True
                        else:
                            evidence["tls"]["server_hello"] = True
                    if _is_tls_record(payload, TLS_RECORD_ALERT):
                        evidence["tls"]["alert_seen"] = True
                        evidence["timeline"].append({"ts": float(pkt.time), "event": "TLS", "detail": f"{direction} ALERT"})

                    # HTTP request/response first lines only
                    if _is_http_request(payload):
                        try:
                            line = payload.split(b"\r\n", 1)[0].decode(errors="ignore")
                            evidence["http"]["requests"].append(line)
                        except Exception:
                            pass
                    elif _is_http_response(payload):
                        try:
                            parts = payload.split(b" ", 2)
                            if len(parts) >= 2 and parts[1].isdigit():
                                evidence["http"]["status_codes"].append(int(parts[1]))
                        except Exception:
                            pass

            # (No extra ICMP block at the bottom; early capture above handles it)

    evidence["meta"]["packet_count"] = count
    return evidence
