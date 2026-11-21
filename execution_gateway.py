"""Policy-enforcing execution boundary for Sentinel's browser-action prototype.

The gateway is adapter-based: it has no browser/network implementation of its
own. Integrations must register narrow, typed action handlers here and must
not expose a second path that bypasses this gateway.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from policy import ActionRequest, ApprovalGrant, TaskContract, authorize_request
from ifc import assess_action_flow


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
        *,
        approval_verifier: Callable[[ApprovalGrant, ActionRequest], bool] | None = None,
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

        if approval_verifier is not None and not callable(approval_verifier):
            raise TypeError("approval_verifier must be callable")

        self._contract = contract
        self._handlers = normalized
        self._approval_verifier = approval_verifier

    def execute(
        self,
        request: ActionRequest,
        approval: ApprovalGrant | None = None,
    ) -> ExecutionResult:
        """Run a registered handler only after policy authorization succeeds."""
        # ApprovalGrant is only a claim, not proof of human authorization.
        # It is ignored unless an explicitly configured trusted verifier
        # authenticates the grant against this exact immutable request.
        verified_approval: ApprovalGrant | None = None
        if isinstance(approval, ApprovalGrant) and self._approval_verifier is not None:
            try:
                if self._approval_verifier(approval, request) is True:
                    verified_approval = approval
            except Exception:
                # Approval verification failures must fail closed.
                verified_approval = None

        decision = authorize_request(request, self._contract, verified_approval)
        action = request.normalized_action

        exact_approval = (
            verified_approval is not None
            and verified_approval.task_id == request.task_id
            and verified_approval.request_fingerprint == decision.request_fingerprint
        )
        flow = assess_action_flow(action, request.untrusted_fields, exact_approval)
        if not decision.allowed or not flow.allowed:
            return ExecutionResult(
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
