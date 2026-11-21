"""Policy-enforcing execution boundary for Sentinel's browser-action prototype.

The gateway is adapter-based: it has no browser/network implementation of its
own. Integrations must register narrow, typed action handlers here and must
not expose a second path that bypasses this gateway.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from policy import ActionRequest, ApprovalGrant, TaskContract, authorize_request\nfrom ifc import assess_action_flow


ActionHandler = Callable[[str, dict[str, Any]], Any]


@dataclass(frozen=True)
class ExecutionResult:
    allowed: bool
    executed: bool
    action: str
    reason: str
    request_fingerprint: str
    output: Any = None


class ExecutionGateway:
    """Authorize each exact request immediately before invoking its handler.

    Handlers receive the immutable request's copied argument snapshot, not the
    caller's original dictionary. ApprovalGrant is only as trustworthy as the
    component that creates it; this gateway does not authenticate humans.
    """

    def __init__(
        self,
        contract: TaskContract,
        handlers: Mapping[str, ActionHandler],
    ) -> None:
        if not isinstance(contract, TaskContract):
            raise TypeError("contract must be a TaskContract")
        if not isinstance(handlers, Mapping):
            raise TypeError("handlers must be a mapping of action names to callables")

        normalized: dict[str, ActionHandler] = {}
        for name, handler in handlers.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError("handler names must be non-empty strings")
            key = name.strip().lower()
            if key in normalized:
                raise ValueError(f"duplicate handler after normalization: {key}")
            if not callable(handler):
                raise TypeError(f"handler for {key} must be callable")
            normalized[key] = handler

        self._contract = contract
        self._handlers = normalized

    def execute(
        self,
        request: ActionRequest,
        approval: ApprovalGrant | None = None,
    ) -> ExecutionResult:
        """Run a registered handler only after policy authorization succeeds."""
        decision = authorize_request(request, self._contract, approval)
        action = request.normalized_action

        exact_approval = (\n            isinstance(approval, ApprovalGrant)\n            and approval.task_id == request.task_id\n            and approval.request_fingerprint == decision.request_fingerprint\n        )\n        flow = assess_action_flow(action, request.untrusted_fields, exact_approval)\n        if not decision.allowed or not flow.allowed:\n            return ExecutionResult(
                allowed=False,
                executed=False,
                action=action,
                reason=decision.reason if not decision.allowed else flow.reason,
                request_fingerprint=decision.request_fingerprint,
            )

        handler = self._handlers.get(action)
        if handler is None:
            return ExecutionResult(
                allowed=False,
                executed=False,
                action=action,
                reason="No execution handler is registered for this action",
                request_fingerprint=decision.request_fingerprint,
            )

        # Use exactly the argument snapshot that was fingerprinted/approved.
        output = handler(request.target_url, request.arguments_for_execution())
        return ExecutionResult(
            allowed=True,
            executed=True,
            action=action,
            reason=decision.reason,
            request_fingerprint=decision.request_fingerprint,
            output=output,
        )
