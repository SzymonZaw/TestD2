"""Experimental, deterministic building blocks for Sentinel AI Web Shield.

This is a research prototype, not a complete prompt-injection detector or a
production security boundary. Proposed actions must be checked independently
of content classification and immediately before the side effect.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Iterable


@dataclass(frozen=True)
class ContentAssessment:
    suspicious: bool
    risk_score: int
    matched_signals: tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    reason: str
    action: str


# Transparent baseline heuristics intended for controlled experiments.
SIGNALS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("ignore_previous_instructions", re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions|"
        r"zignoruj\s+(wszystkie\s+)?(poprzednie|wcześniejsze)\s+instrukcje", re.I), 35),
    ("system_prompt_disclosure", re.compile(
        r"reveal|print|show|disclose\s+(the\s+)?(system\s+prompt|hidden\s+instructions)|"
        r"ujawnij\s+(prompt|instrukcje)", re.I), 30),
    ("secret_exfiltration", re.compile(
        r"(send|email|post|upload|transmit)\s+.{0,50}(password|secret|api\s*key|token|cookie)|"
        r"(wyślij|prześlij|opublikuj).{0,50}(hasło|sekret|token|klucz\s+api)", re.I), 40),
    ("authority_impersonation", re.compile(
        r"(developer|system|administrator)\s+(message|instruction):|"
        r"(wiadomość|instrukcja)\s+(systemowa|administratora):", re.I), 15),
    ("tool_manipulation", re.compile(
        r"(call|invoke|use)\s+(the\s+)?(browser|shell|terminal|tool)|"
        r"(uruchom|wywołaj)\s+(narzędzie|terminal|powłokę)", re.I), 20),
)


def assess_web_content(content: str, threshold: int = 30) -> ContentAssessment:
    """Score visible text using explainable patterns; not semantic proof."""
    if not isinstance(content, str):
        raise TypeError("content must be a string")
    if isinstance(threshold, bool) or not isinstance(threshold, int) or not 0 <= threshold <= 100:
        raise ValueError("threshold must be an integer between 0 and 100")
    matches = [(name, weight) for name, pattern, weight in SIGNALS if pattern.search(content)]
    score = min(100, sum(weight for _, weight in matches))
    names = tuple(name for name, _ in matches)
    return ContentAssessment(
        suspicious=score >= threshold,
        risk_score=score,
        matched_signals=names,
        explanation=("Matched: " + ", ".join(names)) if names else "No configured signal matched",
    )


# Default is deliberately conservative. Deployments must explicitly configure
# the actions that an agent is allowed to perform for a given task.
DEFAULT_ALLOWED_ACTIONS = frozenset({"read_page", "extract_text", "take_screenshot"})


def authorize_action(
    action: str,
    allowed_actions: Iterable[str] = DEFAULT_ALLOWED_ACTIONS,
) -> ActionDecision:
    """Allow only explicitly listed operation names; unknown actions deny by default.

    This operation-only helper is suitable for the current prototype UI. It is
    not sufficient for production execution: use policy.authorize_request to
    bind authorization to a task, target origin, and exact action arguments.
    """
    normalized = action.strip().lower() if isinstance(action, str) else ""
    if not normalized:
        return ActionDecision(False, "Empty or invalid action name", str(action))
    configured = {
        item.strip().lower()
        for item in allowed_actions
        if isinstance(item, str) and item.strip()
    }
    if normalized in configured:
        return ActionDecision(True, "Action is present in the task allowlist", normalized)
    return ActionDecision(False, "Action is not allowlisted", normalized)


def evaluate_proposal(
    page_content: str,
    action: str,
    allowed_actions: Iterable[str] = DEFAULT_ALLOWED_ACTIONS,
) -> dict[str, Any]:
    """Evaluate content and action separately; content score never grants authority."""
    content = assess_web_content(page_content)
    decision = authorize_action(action, allowed_actions)
    return {"content": asdict(content), "action": asdict(decision)}
