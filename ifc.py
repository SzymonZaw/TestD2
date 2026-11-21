"""Conservative information-flow checks for action execution.

This first IFC layer consumes explicit taint metadata carried by ActionRequest.
It blocks tainted inputs from sensitive sinks unless a trusted approval component
has approved the exact request fingerprint (which includes the taint labels).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet

from policy import SENSITIVE_ACTIONS


@dataclass(frozen=True)
class FlowDecision:
    allowed: bool
    reason: str
    action: str
    untrusted_fields: tuple[str, ...]


def assess_action_flow(
    action: str,
    untrusted_fields: FrozenSet[str],
    exact_approval: bool = False,
) -> FlowDecision:
    """Check whether tainted argument fields may flow into an action sink."""
    if not isinstance(action, str) or not action.strip():
        raise ValueError("action must be a non-empty string")
    if isinstance(untrusted_fields, str):
        raise TypeError("untrusted_fields must be a collection of field names")
    fields = tuple(sorted(untrusted_fields))
    if any(not isinstance(item, str) or not item.strip() for item in fields):
        raise ValueError("untrusted field names must be non-empty strings")

    normalized = action.strip().lower()
    if not fields:
        return FlowDecision(True, "No explicitly tainted argument fields", normalized, ())
    if normalized not in SENSITIVE_ACTIONS:
        return FlowDecision(True, "Tainted data does not flow to a configured sensitive sink", normalized, fields)
    if exact_approval:
        return FlowDecision(True, "Tainted data flow has exact request approval", normalized, fields)
    return FlowDecision(
        False,
        "Blocked: untrusted argument data cannot flow to a sensitive action without exact approval",
        normalized,
        fields,
    )
