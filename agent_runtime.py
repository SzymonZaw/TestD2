"""Bounded agent loop that can act only through ExecutionGateway.

The planner proposes typed actions; it never receives a Playwright Page or a
browser handle. Every proposal is converted to an immutable ActionRequest and
sent through the gateway. Page observations remain TrackedText so web content
keeps its UNTRUSTED label when included in later action arguments.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from execution_gateway import ExecutionGateway, ExecutionResult
from policy import ActionRequest, ApprovalGrant
from provenance import TrackedText


@dataclass(frozen=True)
class AgentProposal:
    action: str
    target_url: str = ""
    arguments: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action, str) or not self.action.strip():
            raise ValueError("proposal action must be a non-empty string")
        if not isinstance(self.target_url, str):
            raise TypeError("proposal target_url must be a string")
        if self.arguments is not None and not isinstance(self.arguments, Mapping):
            raise TypeError("proposal arguments must be a mapping or None")


@dataclass(frozen=True)
class AgentObservation:
    action: str
    target_url: str
    result: ExecutionResult


@dataclass(frozen=True)
class AgentRunResult:
    task_id: str
    observations: tuple[AgentObservation, ...]
    stopped_reason: str
    completed: bool


Planner = Callable[[tuple[AgentObservation, ...]], AgentProposal | None]
ApprovalProvider = Callable[[ActionRequest], ApprovalGrant | None]


class BrowserAgentRuntime:
    """Run a bounded planner loop with no browser access outside the gateway.

    A planner returns one proposal per invocation. Returning None ends the run.
    The optional approval provider must be a trusted, separately authenticated
    human-approval boundary; this runtime does not authenticate approvals.
    """

    def __init__(
        self,
        task_id: str,
        gateway: ExecutionGateway,
        planner: Planner,
        approval_provider: ApprovalProvider | None = None,
        max_steps: int = 8,
    ) -> None:
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("task_id must be a non-empty string")
        if not isinstance(gateway, ExecutionGateway):
            raise TypeError("gateway must be an ExecutionGateway")
        if not callable(planner):
            raise TypeError("planner must be callable")
        if approval_provider is not None and not callable(approval_provider):
            raise TypeError("approval_provider must be callable")
        if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps < 1:
            raise ValueError("max_steps must be a positive integer")
        self._task_id = task_id
        self._gateway = gateway
        self._planner = planner
        self._approval_provider = approval_provider
        self._max_steps = max_steps

    def run(self) -> AgentRunResult:
        observations: list[AgentObservation] = []
        for _ in range(self._max_steps):
            proposal = self._planner(tuple(observations))
            if proposal is None:
                return AgentRunResult(
                    self._task_id, tuple(observations), "planner_finished", True
                )
            if not isinstance(proposal, AgentProposal):
                return AgentRunResult(
                    self._task_id, tuple(observations),
                    "planner_returned_invalid_proposal", False
                )

            request = ActionRequest.from_tracked_arguments(
                task_id=self._task_id,
                action=proposal.action,
                target_url=proposal.target_url,
                arguments=proposal.arguments,
            )
            approval = (
                self._approval_provider(request)
                if self._approval_provider is not None else None
            )
            result = self._gateway.execute(request, approval)
            observations.append(
                AgentObservation(proposal.action, proposal.target_url, result)
            )
            if not result.allowed or not result.executed:
                return AgentRunResult(
                    self._task_id, tuple(observations), "gateway_denied_action", False
                )
        return AgentRunResult(
            self._task_id, tuple(observations), "step_limit_reached", False
        )
