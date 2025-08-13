# app/api/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Literal
from pathlib import Path
from datetime import datetime
import json

from app.core.parse import parse_pcap_for_pair
from app.core.verdicts import compute_connectivity_verdict
from app.core import report as report_mod

app = FastAPI(title="PCAP Analyst API", version="0.1.0")

@app.get("/health", tags=["system"])
def health():
    return {"ok": True}

# ----- Schemas -----
class AnalyzeRequest(BaseModel):
    pcap_path: str
    src: str
    dst: str
    sport: Optional[int] = None
    dport: Optional[int] = None
    proto: Literal["tcp", "udp", "icmp"] = "tcp"
    out_dir: Optional[str] = "reports"  # base folder for artifacts

class AnalyzeResponse(BaseModel):
    ok: bool
    verdict: dict
    evidence_path: str
    report_path: str

# ----- Endpoint -----
@app.post("/analyze", response_model=AnalyzeResponse, tags=["analyze"])
def analyze(req: AnalyzeRequest):
    pcap = Path(req.pcap_path)
    if not pcap.exists():
        raise HTTPException(status_code=400, detail=f"pcap_path not found: {pcap}")

    # Run core analysis
    evidence = parse_pcap_for_pair(
        pcap_path=pcap,
        src=req.src,
        dst=req.dst,
        sport=req.sport,
        dport=req.dport,
        proto=req.proto,
    )

    verdict = compute_connectivity_verdict(evidence)

    # Write artifacts to a unique job directory
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    job_dir = Path(req.out_dir) / f"job-{ts}"
    job_dir.mkdir(parents=True, exist_ok=True)

    evidence_path = job_dir / "evidence.json"
    with evidence_path.open("w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    md_text = report_mod.build_markdown_report(evidence, verdict)
    report_path = job_dir / "connectivity_report.md"
    report_path.write_text(md_text, encoding="utf-8")

    return AnalyzeResponse(
        ok=True,
        verdict=verdict,
        evidence_path=str(evidence_path),
        report_path=str(report_path),
    )
