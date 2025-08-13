# app/api/main.py
from fastapi import FastAPI

app = FastAPI(title="PCAP Analyst API", version="0.1.0")

@app.get("/health")
def health():
    return {"ok": True}
