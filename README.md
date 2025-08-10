# PCAP Analyst — Phase 1

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m app.cli analyze path/to/sample.pcap --src 10.0.0.10 --dst 10.0.0.20 --dport 443 --proto tcp --out ./reports
```

Artifacts appear in `./reports/evidence.json` and `./reports/connectivity_report.md`.

### Notes
- Designed for offline PCAPs; no root required to read files.
- TLS/HTTP detection uses minimal heuristics to keep deps light on the Pi.
- For deeper parsing (DNS names, TLS alert descriptions), we’ll optionally add PyShark/TShark later.
