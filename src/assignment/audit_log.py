"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from uuid import uuid4


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}
        self._active_by_user: dict[str, str] = {}

    def record_input(
        self, *, user_id: str, text: str, request_id: str | None = None
    ) -> str:
        """Start an audit record and return its correlation ``request_id``."""
        correlation_id = (
            request_id.strip()
            if isinstance(request_id, str) and request_id.strip()
            else f"REQ-{uuid4().hex}"
        )
        if correlation_id in self._open:
            raise ValueError(f"request_id is already active: {correlation_id}")

        self._open[correlation_id] = {
            "request_id": correlation_id,
            "user_id": str(user_id),
            "input": text if isinstance(text, str) else str(text),
            "input_timestamp": utc_now_iso(),
            "started_at": perf_counter(),
        }
        self._active_by_user[str(user_id)] = correlation_id
        return correlation_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
        action: str | None = None,
        action_decision: str | None = None,
        reviewer_id: str | None = None,
        reviewer_decision: str | None = None,
        approval_id: str | None = None,
    ) -> str:
        """Finish and store an interaction using the input correlation ID."""
        correlation_id = (
            request_id.strip()
            if isinstance(request_id, str) and request_id.strip()
            else self._active_by_user.get(str(user_id))
        )
        if not correlation_id:
            correlation_id = f"REQ-{uuid4().hex}"

        pending = self._open.pop(correlation_id, None)
        if pending is None:
            # Preserve an output/error event even if the input hook was missed.
            pending = {
                "request_id": correlation_id,
                "user_id": str(user_id),
                "input": None,
                "input_timestamp": None,
                "started_at": perf_counter(),
            }

        if self._active_by_user.get(str(user_id)) == correlation_id:
            self._active_by_user.pop(str(user_id), None)

        finished_at = perf_counter()
        processing_time_ms = round(
            max(0.0, (finished_at - pending.pop("started_at")) * 1000), 3
        )
        record = {
            **pending,
            "output": text if isinstance(text, str) else str(text),
            "output_timestamp": utc_now_iso(),
            "processing_time_ms": processing_time_ms,
            # Keep the common alias for consumers that call this latency.
            "latency_ms": processing_time_ms,
            "blocked": bool(blocked),
            "layer": layer or "unclassified",
            "action": action,
            "action_decision": action_decision or (
                "blocked" if blocked else "allowed"
            ),
            "reviewer_id": reviewer_id,
            "reviewer_decision": reviewer_decision or "not_required",
            "approval_id": approval_id,
        }
        self.logs.append(record)
        return correlation_id

    def find_by_request_id(self, request_id: str) -> list[dict]:
        """Return completed audit records for a correlation ID."""
        return [record for record in self.logs if record["request_id"] == request_id]

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as file:
            json.dump(self.logs, file, indent=2, ensure_ascii=False)
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
