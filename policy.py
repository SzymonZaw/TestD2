"""Task-scoped authorization for proposed browser-agent actions.

The policy engine is deterministic and deliberately separate from the LLM.
It authorizes an exact action request, not merely a tool name. The caller must
invoke it at the execution boundary immediately before performing a side effect.

ApprovalGrant is a data transfer object: only a trusted application component
may create/pass one after authenticating a human approval. This module does not
authenticate users, persist approvals, or provide a production-grade token.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ActionRequest:
    task_id: str
    action: str
    target_url: str = ""
    arguments: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not self.task_id.strip():
            raise ValueError("task_id must be a non-empty string")
        if not isinstance(self.action, str) or not self.action.strip():
            raise ValueError("action must be a non-empty string")
        if not isinstance(self.target_url, str):
            raise TypeError("target_url must be a string")
        if self.arguments is not None and not isinstance(self.arguments, Mapping):
            raise TypeError("arguments must be a mapping or None")

    @property
    def normalized_action(self) -> str:
        return self.action.strip().lower()

    def fingerprint(self) -> str:
        """Hash task, operation, target and arguments using canonical JSON."""
        payload = {
            "task_id": self.task_id,
            "action": self.normalized_action,
            "target_url": self.target_url,
            "arguments": self.arguments or {},
        }
        try:
            encoded = json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("action arguments must be JSON-serializable finite values") from exc
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class TaskContract:
    task_id: str
    allowed_actions: frozenset[str]
    allowed_origins: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not self.task_id.strip():
            raise ValueError("task_id must be a non-empty string")
        actions = frozenset(
            item.strip().lower() for item in self.allowed_actions
            if isinstance(item, str) and item.strip()
        )
        origins = frozenset(_normalize_origin(item) for item in self.allowed_origins)
        object.__setattr__(self, "allowed_actions", actions)
        object.__setattr__(self, "allowed_origins", origins)


@dataclass(frozen=True)
class ApprovalGrant:
    """Approval for one exact request fingerprint within one task."""
    task_id: str
    request_fingerprint: str


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    action: str
    request_fingerprint: str


def _normalize_origin(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("allowed origins must be non-empty URLs")
    parsed = urlsplit(url.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"invalid HTTP(S) origin: {url!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials are not allowed in origins")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("allowed origins must not contain a path, query or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid port in origin: {url!r}") from exc
    scheme = parsed.scheme.lower()
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    default_port = 80 if scheme == "http" else 443
    suffix = "" if port is None or port == default_port else f":{port}"
    return f"{scheme}://{host}{suffix}"


def _request_origin(target_url: str) -> str | None:
    if not target_url:
        return None
    parsed = urlsplit(target_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    scheme = parsed.scheme.lower()
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    default_port = 80 if scheme == "http" else 443
    suffix = "" if port is None or port == default_port else f":{port}"
    return f"{scheme}://{host}{suffix}"


def authorize_request(
    request: ActionRequest,
    contract: TaskContract,
    approval: ApprovalGrant | None = None,
) -> PolicyDecision:
    """Authorize a request against task scope, origin constraints and exact approval."""
    if not isinstance(request, ActionRequest) or not isinstance(contract, TaskContract):
        raise TypeError("request and contract must use their declared types")
    fingerprint = request.fingerprint()
    action = request.normalized_action

    if request.task_id != contract.task_id:
        return PolicyDecision(False, "Request task does not match the active task contract", action, fingerprint)

    if request.target_url:
        origin = _request_origin(request.target_url)
        if not origin:
            return PolicyDecision(False, "Target must be a valid HTTP(S) URL without embedded credentials", action, fingerprint)
        if origin not in contract.allowed_origins:
            return PolicyDecision(False, "Target origin is outside the task contract", action, fingerprint)

    if action in contract.allowed_actions:
        return PolicyDecision(True, "Action and target are within the task contract", action, fingerprint)

    if (
        isinstance(approval, ApprovalGrant)
        and approval.task_id == request.task_id
        and approval.request_fingerprint == fingerprint
    ):
        return PolicyDecision(True, "Exact action request has an approval grant", action, fingerprint)

    return PolicyDecision(False, "Action is not permitted by the task contract and has no matching approval", action, fingerprint)
