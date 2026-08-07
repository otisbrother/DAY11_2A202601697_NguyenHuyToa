"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 11: Confidence Router
  TODO 12: Design 3 HITL decision points
"""
from dataclasses import dataclass
import math


# ============================================================
# TODO 11: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        normalized_action = (
            action_type.strip().lower() if isinstance(action_type, str) else ""
        )

        # Invalid model confidence is not evidence of safety. Route it to a
        # human instead of silently treating it as high confidence.
        try:
            score = float(confidence)
        except (TypeError, ValueError):
            score = float("nan")

        if normalized_action in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=score,
                reason=f"High-risk action: {normalized_action}",
                priority="high",
                requires_human=True,
            )

        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            return RoutingDecision(
                action="escalate",
                confidence=score,
                reason="Invalid confidence score — escalating",
                priority="high",
                requires_human=True,
            )

        if score >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=score,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )

        if score >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=score,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )

        return RoutingDecision(
            action="escalate",
            confidence=score,
            reason="Low confidence — escalating",
            priority="high",
            requires_human=True,
        )


# ============================================================
# TODO 12: Design 3 HITL decision points + a review lifecycle
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
# - approval_path: What approve/reject/timeout decision is recorded?
# - audit_fields: Which correlation ID, intent and proposed action/diff are logged?
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Money transfer or beneficiary change",
        "trigger": (
            "Any transfer_money request, any new or changed beneficiary, or a "
            "transfer with an amount/device/recipient anomaly. Model confidence "
            "never bypasses this review."
        ),
        "hitl_model": "human-in-the-loop — approval is required before execution",
        "context_needed": (
            "Proposed action and intent; authenticated customer; old and new "
            "beneficiary name, account and bank; amount and currency; available "
            "balance; recent transfers; device/session risk and anomaly signals; "
            "agent rationale; and an explicit before/after diff."
        ),
        "example": (
            "The agent proposes replacing beneficiary A with beneficiary B and "
            "sending VND 50,000,000 after a login from a new device."
        ),
        "approval_path": (
            "approve: record reviewer approval, then release only the reviewed "
            "action through the action/egress policy; reject: cancel it and notify "
            "the customer; timeout: place the request on hold and do not transfer "
            "money or change the beneficiary. Never auto-send on timeout."
        ),
        "audit_fields": (
            "request_id, intent, proposed_action, before_state, after_state, diff, "
            "amount, anomaly_signals, reviewer_id, reviewer_decision, review_reason, "
            "approval_id, created_at, decided_at, layer=hitl.transfer_beneficiary"
        ),
    },
    {
        "id": 2,
        "name": "Account closure or customer-data deletion",
        "trigger": (
            "Any close_account or delete_data proposal, including a request quoted "
            "from email/RAG or one submitted with high model confidence."
        ),
        "hitl_model": "human-in-the-loop — a responsible operations reviewer decides",
        "context_needed": (
            "Proposed action and customer intent; identity-verification status; "
            "account balance; pending transfers, fees and disputes; linked products; "
            "retention/legal obligations; affected records; and deletion/closure diff."
        ),
        "example": (
            "The agent proposes closing an account that still has a pending card "
            "dispute and deleting its customer-service history."
        ),
        "approval_path": (
            "approve: record approval and execute only the reviewed closure/deletion "
            "scope; reject: preserve the account/data and return the reason; timeout: "
            "reject the operation and keep all state unchanged."
        ),
        "audit_fields": (
            "request_id, intent, proposed_action, affected_resources, before_state, "
            "after_state, diff, verification_status, reviewer_id, reviewer_decision, "
            "review_reason, approval_id, created_at, decided_at, "
            "layer=hitl.account_lifecycle"
        ),
    },
    {
        "id": 3,
        "name": "Credential or personal-information update",
        "trigger": (
            "Any change_password or update_personal_info proposal, especially a "
            "phone/email/address change followed by account recovery or payment."
        ),
        "hitl_model": "human-in-the-loop — identity/risk reviewer must approve",
        "context_needed": (
            "Proposed action and intent; authentication and step-up verification; "
            "masked old/new values; device and session history; recent profile "
            "changes; fraud alerts; downstream access impact; and before/after diff."
        ),
        "example": (
            "A new device asks to replace the registered phone and email, then reset "
            "the password and add a beneficiary."
        ),
        "approval_path": (
            "approve: record approval and apply exactly the reviewed fields; reject: "
            "discard the changes and protect the existing credentials; timeout: hold "
            "the request until re-verification, with no automatic profile update."
        ),
        "audit_fields": (
            "request_id, intent, proposed_action, masked_before_state, "
            "masked_after_state, diff, risk_signals, reviewer_id, reviewer_decision, "
            "review_reason, approval_id, created_at, decided_at, "
            "layer=hitl.identity_change"
        ),
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
