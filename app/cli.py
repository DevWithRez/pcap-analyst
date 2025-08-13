# app/cli.py
from pathlib import Path
from app.core.verdicts import compute_connectivity_verdict
from app.core import report  # uses build_markdown_report()
import argparse
import json
import os
from pathlib import Path

from app.core.parse import parse_pcap_for_pair

def main():
    ap = argparse.ArgumentParser(prog="pcap-analyst", description="PCAP Analyst :: basic evidence export")
    ap.add_argument("pcap", help="Path to .pcap/.pcapng")
    ap.add_argument("--src", required=True, help="Source IP")
    ap.add_argument("--dst", required=True, help="Destination IP")
    ap.add_argument("--sport", type=int, help="Source port (optional)")
    ap.add_argument("--dport", type=int, help="Destination port (optional)")
    ap.add_argument("--proto", choices=["tcp", "udp", "icmp"], default="tcp", help="L4 protocol filter")
    ap.add_argument("--out", default="./reports", help="Output directory (default: ./reports)")
    ap.add_argument("--max-packets", type=int, default=None, help="(reserved) cap packets for quick tests")
    args = ap.parse_args()

    # parse
    evidence = parse_pcap_for_pair(
        pcap_path=Path(args.pcap),
        src=args.src,
        dst=args.dst,
        sport=args.sport,
        dport=args.dport,
        proto=args.proto,
    )

    # write evidence.json
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    ev_path = out_dir / "evidence.json"
    with ev_path.open("w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)
    # --- NEW: verdict + markdown report ---
    verdict = compute_connectivity_verdict(evidence)

    md_text = report.build_markdown_report(evidence, verdict)

    md_path = out_dir / "connectivity_report.md"
    md_path.write_text(md_text, encoding="utf-8")

    print(f"Report written: {md_path}")
    # --- END NEW ---


    # console summary
    meta = evidence.get("meta", {})
    tcp  = evidence.get("tcp", {})
    icmp = evidence.get("icmp", {})
    tls  = evidence.get("tls", {})
    http = evidence.get("http", {})

    print("== PCAP Analyst :: BASIC EVIDENCE ==")
    print(f"PCAP: {os.path.abspath(args.pcap)}")
    print(f"Filters: src={meta.get('src')} dst={meta.get('dst')} sport={meta.get('sport')} dport={meta.get('dport')} proto={meta.get('proto')}")
    print(f"Packets (file): {meta.get('packet_count')}")
    if meta.get('proto') == 'tcp':
        print(f"TCP: SYN={int(tcp.get('syn_seen', False))} SYN-ACK={int(tcp.get('synack_seen', False))} ACK={int(tcp.get('ack_seen', False))} RST={int(tcp.get('server_rst', False))} FIN={int(tcp.get('fin_seen', False))}")
        print(f"TCP retransmissions (coarse): client={tcp.get('client_retx',0)} server={tcp.get('server_retx',0)}")
    if icmp.get("unreachables"):
        print(f"ICMP unreachables/time-exceeded: {len(icmp['unreachables'])}")
    if tls:
        print(f"TLS hints: client_hello={tls.get('client_hello')} server_hello={tls.get('server_hello')} alert={tls.get('alert_seen')}")
    if http:
        sc = http.get('status_codes', [])
        print(f"HTTP: requests={len(http.get('requests',[]))} status_codes={sc[:5]}{'...' if len(sc)>5 else ''}")
    print(f"Artifact written: {ev_path}")

if __name__ == "__main__":
    main()
