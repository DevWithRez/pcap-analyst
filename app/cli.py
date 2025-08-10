"""
Command-line entrypoint.
- Parses user intent (pcap path, src/dst, ports, proto, mode, out dir)
- Runs a simple pipeline: preflight -> parse -> heuristics -> report
- Writes evidence.json and connectivity_report.md to the output folder
"""
import argparse
import json
from pathlib import Path

from app.core.ingest import preflight
from app.core.parse import parse_pcap_for_pair
from app.core.heuristics import analyze_connectivity
from app.core.report import build_markdown_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pcap-analyst",
        description="Analyze PCAPs for connectivity (and optionally threat) insights.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a PCAP")
    analyze.add_argument("pcap", type=Path, help="Path to .pcap or .pcapng")
    analyze.add_argument("--src", required=True, help="Source IP")
    analyze.add_argument("--dst", required=True, help="Destination IP")
    analyze.add_argument("--sport", type=int, help="Source port")
    analyze.add_argument("--dport", type=int, help="Destination port")
    analyze.add_argument("--proto", choices=["tcp", "udp", "icmp"], default="tcp", help="Layer-4 protocol filter")
    analyze.add_argument("--mode", choices=["connectivity", "threat"], default="connectivity")
    analyze.add_argument("--out", type=Path, default=Path("reports"), help="Output directory (default: ./reports)")
    return p


def cmd_analyze(args) -> int:
    # 1) Preflight: make sure file exists; create output dir; collect metadata
    pcap_path, meta = preflight(args.pcap, args.out, {
        "src": args.src, "dst": args.dst, "sport": args.sport, "dport": args.dport, "proto": args.proto,
        "mode": args.mode,
    })

    # 2) Parse: scan packets and extract compact evidence for this src/dst pair
    evidence = parse_pcap_for_pair(
        pcap_path=pcap_path,
        src=args.src,
        dst=args.dst,
        sport=args.sport,
        dport=args.dport,
        proto=args.proto,
    )

    # 3) Heuristics: compute a human-readable verdict (Connected/Partial/Failed)
    verdict = analyze_connectivity(evidence)

    # 4) Persist: write evidence.json + markdown report
    evidence_path = args.out / "evidence.json"
    report_path = args.out / "connectivity_report.md"
    with evidence_path.open("w") as f:
        json.dump(evidence, f, indent=2)

    report_md = build_markdown_report(evidence, verdict)
    report_path.write_text(report_md)

    # 5) Console summary: prints a one-screen overview
    print("== PCAP Analyst :: Phase 1 ==")
    print(f"PCAP:       {pcap_path}")
    print(f"SRC → DST:  {args.src} → {args.dst}")
    print(f"SPORT/DPORT:{args.sport} / {args.dport}")
    print(f"PROTO:      {args.proto}")
    print(f"MODE:       {args.mode}")
    print(f"VERDICT:    {verdict.get('status')} ({verdict.get('reason_code')})")
    print(f"ARTIFACTS:  {evidence_path} , {report_path}")
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "analyze":
        raise SystemExit(cmd_analyze(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
