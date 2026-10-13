"""In-memory rule-based demonstration API; does not verify hardware TPM quotes."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .base import AuditLogger, SecurityException
from .models import SystemTaskPayload
from .supervisor import SystemSupervisor

supervisor = SystemSupervisor(model_provider="mock")

app = FastAPI(
    title="TPM Measurement Quote Agent — Rule-based Demo",
    description="Illustrative numeric/descriptor rules, not hardware TPM attestation.",
    version="3.0.0-ENTERPRISE",
)


class ChatRequest(BaseModel):
    query: str


@app.get("/health")
def health():
    return {
        "status": "HEALTHY", "service": "tpm-2-measurement-quote-agent",
        "domain": "Rule-based audit demonstration",
        "standard": "No TPM/FIPS/NIST conformance determination",
        "version": "3.0.0-ENTERPRISE",
    }


@app.get("/metrics")
def metrics():
    return {
        "dossiers_processed_total": len(supervisor.dossier_registry),
        "audit_blocks_total": len(AuditLogger.get_trail()),
        "system_status": "DEMO_ACTIVE",
    }


@app.post("/api/audit")
def api_audit(payload: SystemTaskPayload):
    try:
        return supervisor.process_task(payload).to_dict()
    except SecurityException as exc:
        raise HTTPException(status_code=400, detail="Potential sensitive identifier rejected") from exc


@app.post("/api/chat")
def api_chat(req: ChatRequest):
    try:
        return {"response": supervisor.query_supervisory_chat(req.query)}
    except SecurityException as exc:
        raise HTTPException(status_code=400, detail="Potential sensitive identifier rejected") from exc


@app.get("/api/audit/logs")
def api_audit_logs():
    return {"audit_trail": AuditLogger.get_trail(), "verified": AuditLogger.verify_integrity()}
