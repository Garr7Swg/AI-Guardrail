from __future__ import annotations

import re
from dataclasses import dataclass


MAX_PROMPT_CHARS = 6_000
MAX_ANSWER_CHARS = 24_000

_INJECTION_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE | re.DOTALL)
    for pattern in (
        r"\b(?:ignore|disregard|override|forget)\b.{0,100}\b(?:previous|prior|system|developer|safety|guardrail|instructions?)\b",
        r"\b(?:reveal|print|repeat|show|expose)\b.{0,80}\b(?:system|developer|hidden)\b.{0,40}\b(?:prompt|instructions?)\b",
        r"\b(?:jailbreak|DAN\s+mode|prompt\s+injection)\b",
        r"\b(?:bypass|disable|remove)\b.{0,60}\b(?:safety|guardrails?|content\s+policy)\b",
    )
)


@dataclass(frozen=True)
class Decision:
    blocked: bool
    reason: str = ""


def _contains_brand(text: str, brands: tuple[str, ...]) -> bool:
    for brand in brands:
        if re.search(r"(?<!\w)" + re.escape(brand) + r"(?!\w)", text, re.IGNORECASE):
            return True
    return False


def inspect_prompt(text: str, brands: tuple[str, ...]) -> Decision:
    if len(text) > MAX_PROMPT_CHARS:
        return Decision(True, "prompt_too_long")
    if _contains_brand(text, brands):
        return Decision(True, "blocked_brand")
    if any(pattern.search(text) for pattern in _INJECTION_PATTERNS):
        return Decision(True, "prompt_injection")
    return Decision(False)


def inspect_answer(text: str, brands: tuple[str, ...]) -> Decision:
    if not text.strip() or len(text) > MAX_ANSWER_CHARS:
        return Decision(True, "invalid_answer")
    if _contains_brand(text, brands):
        return Decision(True, "blocked_brand")
    return Decision(False)
