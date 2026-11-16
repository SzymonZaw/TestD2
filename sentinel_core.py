"""Experimental, deterministic building blocks for Sentinel AI Web Shield.

This is a research prototype, not a complete prompt-injection detector or a
production security boundary. Run proposed actions through an independent
policy decision even when page content is classified as benign.
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
        r"ignore\\s+(all\\s+)?(previous|prior|above)\\s+instructions|"
        r"zignoruj\\s+(wszystkie\\s+)?(poprzednie|wcześniejsze)\\s+instrukcje", re.I), 35),
    ("system_prompt_disclosure", re.compile(
        r"reveal|print|show|disclose\\s+(the\\s+)?(system\\s+prompt|hidden\\s+instructions)|"
        r"ujawnij\\s+(prompt|instrukcje)", re.I), 30),
    ("secret_exfiltration", re.compile(
        r"(send|email|post|upload|transmit)\\s+.{0,50}(password|secret|api\\s*key|token|cookie)|"
        r"(wyślij|prześlij|opublikuj).{0,50}(hasło|sekret|token|klucz\\s+api)", re.I), 40),
    ("authority_impersonation", re.compile(
        r"(developer|system|administrator)\\s+(message|instruction):|"
        r"(wiadomość|instrukcja)\\s+(systemowa|administratora):", re.I), 15),
    ("tool_manipulation", re.compile(
        r"(call|invoke|use)\\s+(the\\s+)?(browser|shell|terminal|tool)|"
        r"(uruchom|wywołaj)\\s+(narzędzie|terminal|powłokę)", re.I), 20),
)


def assess_web_content(content: str, threshold: int = 30) -> ContentAssessment:
    """Score visible text using explainable patterns; not semantic proof."""
    if not isinstance(content, str):
        raise TypeError("content must be a string")
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
    *,
    user_approved: bool = False,
) -> ActionDecision:
    """Independent allowlist gate. Unknown actions are denied by default."""
    normalized = action.strip().lower() if isinstance(action, str) else ""
    if not normalized:
        return ActionDecision(False, "Empty or invalid action name", str(action))
    if normalized in set(allowed_actions):
        return ActionDecision(True, "Action is present in the task allowlist", normalized)
    if user_approved:
        return ActionDecision(True, "Explicit user approval recorded", normalized)
    return ActionDecision(False, "Action is not allowlisted; explicit approval required", normalized)


def evaluate_proposal(page_content: str, action: str, allowed_actions: Iterable[str] = DEFAULT_ALLOWED_ACTIONS) -> dict[str, Any]:
    """Evaluate content and action separately; content score never grants authority."""
    content = assess_web_content(page_content)
    decision = authorize_action(action, allowed_actions)
    return {"content": asdict(content), "action": asdict(decision)}
