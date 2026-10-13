"""Illustrative rule evaluators. These do not perform TPM or standards conformance checks."""
import uuid
from typing import List
from .models import SystemTaskPayload, AgentAlert, UrgencyLevel

REFERENCE = "Educational demonstration rules, not a TCG/NIST/FIPS standard"


class InvariantQCWorker:
    @classmethod
    def evaluate(cls, payload: SystemTaskPayload) -> List[AgentAlert]:
        if payload.primary_metric <= 25.0:
            return []
        return [AgentAlert(
            alert_id=f"QC-{uuid.uuid4().hex[:6]}",
            origin_worker="InvariantQCWorker",
            urgency=UrgencyLevel.ELEVATED,
            summary="Primary Metric Threshold Exceeded",
            technical_details=f"Primary measurement ({payload.primary_metric:.2f}) exceeds the illustrative 25.00 threshold.",
            actionable_remediation="Review the input and configured demonstration threshold.",
            standard_reference=REFERENCE,
        )]


class SafetyEscalationWorker:
    @classmethod
    def evaluate(cls, payload: SystemTaskPayload) -> List[AgentAlert]:
        if not payload.is_critical_flag and payload.secondary_metric <= 12.0:
            return []
        return [AgentAlert(
            alert_id=f"SAFE-{uuid.uuid4().hex[:6]}",
            origin_worker="SafetyEscalationWorker",
            urgency=UrgencyLevel.CRITICAL_STAT if payload.is_critical_flag else UrgencyLevel.ELEVATED,
            summary="Illustrative Escalation Condition Triggered",
            technical_details=f"CriticalFlag={payload.is_critical_flag} with secondary index {payload.secondary_metric:.2f}.",
            actionable_remediation="Review the demonstration inputs and escalation rules.",
            standard_reference=REFERENCE,
        )]


class ProtocolConformanceWorker:
    @classmethod
    def evaluate(cls, payload: SystemTaskPayload) -> List[AgentAlert]:
        descriptor = str(payload.status_descriptor).upper()
        if not any(w in descriptor for w in ("DISCORDANT", "ANOMALY", "MUTANT", "VIOLATION", "FAIL", "REJECT")):
            return []
        return [AgentAlert(
            alert_id=f"CONF-{uuid.uuid4().hex[:6]}",
            origin_worker="ProtocolConformanceWorker",
            urgency=UrgencyLevel.ELEVATED,
            summary="Descriptor Anomaly Keyword Detected",
            technical_details=f"Descriptor '{payload.status_descriptor}' matched an example anomaly keyword, not a verified protocol failure.",
            actionable_remediation="Review the descriptor against actual system requirements.",
            standard_reference=REFERENCE,
        )]
