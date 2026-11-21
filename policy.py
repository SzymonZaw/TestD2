"""Task-scoped authorization for proposed browser-agent actions.

The policy engine is deterministic and deliberately separate from the LLM.
It authorizes an exact action request, not merely a tool name. The caller must
invoke it at the execution boundary immediately before performing a side effect.

ApprovalGrant is a data transfer object: only a trusted application component
may create/pass one after authenticating a human approval. This module does not
authenticate users, persist approvals, or provide a production-grade token.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit

from provenance import TrackedText, TrustLabel


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


@dataclass(frozen=True)
class ActionRequest:
    task_id: str
    action: str
    target_url: str = ""
    arguments: Mapping[str, Any] | None = None
    untrusted_fields: frozenset[str] = frozenset()
    _arguments_json: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not self.task_id.strip():
            raise ValueError("task_id must be a non-empty string")
        if not isinstance(self.action, str) or not self.action.strip():
            raise ValueError("action must be a non-empty string")
        if not isinstance(self.target_url, str):
            raise TypeError("target_url must be a string")
        if self.arguments is not None and not isinstance(self.arguments, Mapping):
            raise TypeError("arguments must be a mapping or None")
        try:
            encoded = json.dumps(
                dict(self.arguments or {}), sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            )
            snapshot = json.loads(encoded)
        except (TypeError, ValueError) as exc:
            raise ValueError("action arguments must be JSON-serializable finite values") from exc
        if not isinstance(snapshot, dict) or not all(isinstance(key, str) for key in snapshot):
            raise ValueError("action arguments must be a JSON object with string keys")
        if isinstance(self.untrusted_fields, str):
            raise TypeError("untrusted_fields must be a collection of top-level argument names")
        fields = frozenset(self.untrusted_fields)
        if any(not isinstance(name, str) or not name.strip() for name in fields):
            raise ValueError("untrusted field names must be non-empty strings")
        if any(name not in snapshot for name in fields):
            raise ValueError("every untrusted field must identify an existing top-level argument")
        object.__setattr__(self, "untrusted_fields", fields)
        object.__setattr__(self, "_arguments_json", json.dumps(
            snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ))
        object.__setattr__(self, "arguments", _freeze_json(snapshot))

    @classmethod
    def from_tracked_arguments(
        cls,
        task_id: str,
        action: str,
        target_url: str = "",
        arguments: Mapping[str, Any] | None = None,
    ) -> "ActionRequest":
        """Build a request and automatically propagate top-level TrackedText labels."""
        values: dict[str, Any] = {}
        untrusted: set[str] = set()
        for name, value in (arguments or {}).items():
            if isinstance(value, TrackedText):
                values[name] = value.value
                if value.provenance.label is TrustLabel.UNTRUSTED:
                    untrusted.add(name)
            else:
                values[name] = value
        return cls(
            task_id=task_id,
            action=action,
            target_url=target_url,
            arguments=values,
            untrusted_fields=frozenset(untrusted),
        )

    @property
    def normalized_action(self) -> str:
        return self.action.strip().lower()

    def arguments_for_execution(self) -> dict[str, Any]:
        """Return a fresh copy of the exact argument snapshot covered by approval."""
        return json.loads(self._arguments_json)

    def fingerprint(self) -> str:
        """Hash task, operation, target and immutable argument snapshot."""
        payload = {
            "task_id": self.task_id,
            "action": self.normalized_action,
            "target_url": self.target_url,
            "arguments": json.loads(self._arguments_json),
            "untrusted_fields": sorted(self.untrusted_fields),
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


SENSITIVE_ACTIONS = frozenset({
    "send_email", "send_message", "post_message", "submit_form",
    "delete_file", "delete_record", "purchase", "upload_file",
    "share_data", "run_shell",
})


@dataclass(frozen=True)
class TaskContract:
    task_id: str
    allowed_actions: frozenset[str]
    allowed_origins: frozenset[str] = frozenset()
    requires_approval: frozenset[str] = SENSITIVE_ACTIONS

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not self.task_id.strip():
            raise ValueError("task_id must be a non-empty string")
        if (
            isinstance(self.allowed_actions, str)
            or isinstance(self.requires_approval, str)
            or isinstance(self.allowed_origins, str)
        ):
            raise TypeError("actions and origins must be collections, not strings")
        actions = frozenset(
            item.strip().lower() for item in self.allowed_actions
            if isinstance(item, str) and item.strip()
        )
        approvals = frozenset(
            item.strip().lower() for item in self.requires_approval
            if isinstance(item, str) and item.strip()
        )
        origins = frozenset(_normalize_origin(item) for item in self.allowed_origins)
        object.__setattr__(self, "allowed_actions", actions)
        object.__setattr__(self, "requires_approval", approvals)
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


def _origin_from_url(url: str) -> str:
    try:
        parsed = urlsplit(url.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL credentials are not allowed")
        port = parsed.port
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid HTTP(S) URL or origin") from exc
    scheme = parsed.scheme.lower()
    default_port = 80 if scheme == "http" else 443
    suffix = "" if port is None or port == default_port else f":{port}"
    return f"{scheme}://{host}{suffix}"


def _normalize_origin(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("allowed origins must be non-empty URLs")
    try:
        parsed = urlsplit(url.strip())
    except ValueError as exc:
        raise ValueError("invalid allowed origin") from exc
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("allowed origins must not contain a path, query or fragment")
    return _origin_from_url(url)


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
        try:
            origin = _origin_from_url(request.target_url)
        except ValueError:
            return PolicyDecision(False, "Target must be a valid HTTP(S) URL without embedded credentials", action, fingerprint)
        if origin not in contract.allowed_origins:
            return PolicyDecision(False, "Target origin is outside the task contract", action, fingerprint)

    exact_approval = (
        isinstance(approval, ApprovalGrant)
        and approval.task_id == request.task_id
        and approval.request_fingerprint == fingerprint
    )

    if action in contract.requires_approval:
        if exact_approval:
            return PolicyDecision(True, "Sensitive action has an exact request approval", action, fingerprint)
        return PolicyDecision(False, "Sensitive action requires approval for this exact request", action, fingerprint)

    if action in contract.allowed_actions:
        return PolicyDecision(True, "Action and target are within the task contract", action, fingerprint)

    if exact_approval:
        return PolicyDecision(True, "Exact action request has an approval grant", action, fingerprint)

    return PolicyDecision(False, "Action is not permitted by the task contract and has no matching approval", action, fingerprint)
