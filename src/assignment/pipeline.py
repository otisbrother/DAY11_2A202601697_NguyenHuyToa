"""
Assignment 11 — Defense-in-depth pipeline assembly (TODO).

Wire rate limiter + lab guardrails + judge + audit + monitoring.
You may use Google ADK plugins, LangGraph, NeMo, or pure Python.
"""
from __future__ import annotations

from urllib.parse import urlparse

from assignment.rate_limiter import RateLimitPlugin
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert
from guardrails.output_guardrails import content_filter


ALLOWED_EGRESS_HOSTS = frozenset({"api.vinbank.example"})


def is_egress_allowed(destination: str, payload: str) -> bool:
    """TODO 8A: Enforce a destination allowlist before any data leaves the agent.

    Return ``True`` only for an approved VinBank HTTPS endpoint and ordinary
    banking payload. Return ``False`` for unknown domains and payloads that
    contain a password, API key, database host, phone number or email address.
    Do not let the LLM's prose decide this policy.
    """
    if not isinstance(destination, str) or not isinstance(payload, str):
        return False

    try:
        parsed = urlparse(destination)
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return False

    # Compare the parsed hostname, never a substring of the original URL.
    # User-info is unnecessary for these API calls and can make URLs deceptive.
    if (
        parsed.scheme.lower() != "https"
        or hostname not in ALLOWED_EGRESS_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
    ):
        return False

    # The same deterministic PII/secret policy protects both customer-facing
    # responses and outbound tool payloads.
    return content_filter(payload)["safe"]


def build_production_plugins(
    *,
    max_requests: int = 10,
    window_seconds: int = 60,
    use_llm_judge: bool = True,
) -> list:
    """
    TODO 8: Return an ordered list of plugins / layers:

    1. RateLimitPlugin
    2. InputGuardrailPlugin  (from guardrails.input_guardrails)
    3. OutputGuardrailPlugin / LlmJudge  (from guardrails.output_guardrails)
    4. (optional) NeMo wrapper

    Audit/monitoring can be plugins or side observers — document your choice.
    The action gateway calls ``is_egress_allowed`` separately before any sink.
    """
    raise NotImplementedError("Implement build_production_plugins")


def build_observability():
    """TODO: return (AuditLogPlugin(), MonitoringAlert())."""
    raise NotImplementedError("Implement build_observability")


async def run_assignment_suite(pipeline, student_id: str) -> dict:
    """
    TODO: Run Tests 1–4 from assignment11.md and
    return a dict matching schemas/results.schema.json.

    Write:
      outputs/results.json
      outputs/audit_log.json
      outputs/metrics.json
    """
    raise NotImplementedError("Implement run_assignment_suite")
