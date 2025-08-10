"""
Preflight checks and setup before parsing.
We keep this separate so parse.py can focus only on packet logic.
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, Tuple


MAX_DEFAULT_BYTES = 1_000_000_000  # 1 GB soft guard; tune in rules/connectivity.yml later


def preflight(pcap: Path, out_dir: Path, meta: Dict) -> Tuple[Path, Dict]:
    """Validate input paths, create output folder, and attach basic file metadata.

    Returns the normalized pcap path and an updated meta dict you can persist.
    """
    if not pcap.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap}")
    if not pcap.is_file():
        raise ValueError(f"Not a file: {pcap}")

    size = pcap.stat().st_size
    if size > MAX_DEFAULT_BYTES:
        # We allow it in Phase 1, but warn loudly; Phase 3 will enforce async/queue
        print(f"[WARN] Large PCAP detected (~{size/1_048_576:.1f} MB). Consider sampling in Phase 1.")

    out_dir.mkdir(parents=True, exist_ok=True)

    meta = dict(meta)
    meta.update({
        "pcap_name": pcap.name,
        "pcap_size": size,
    })
    return pcap.resolve(), meta
