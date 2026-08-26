"""Deterministic, read-only scanning of untrusted Technocore room content.

This module deliberately performs no I/O.  In particular, URLs found in text are
never opened, resolved, or fetched; they are only matched and redacted locally.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit


class ScanCategory(str, Enum):
    """Stable public categories emitted by :func:`scan_text`."""

    PROMPT_INJECTION = "prompt_injection"
    COMMAND_EXECUTION = "command_execution"
    WALLET_SECRET_SOLICITATION = "wallet_secret_solicitation"
    SUSPICIOUS_URL = "suspicious_url"
    REPETITIVE_FARMING = "repetitive_farming"


class Severity(str, Enum):
    """Relative urgency of a deterministic finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class Finding:
    """An immutable, explainable match against untrusted text."""

    category: ScanCategory
    severity: Severity
    rule: str
    excerpt: str


_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`]+", re.IGNORECASE)
_WORD_RE = re.compile(r"[\w'-]+", re.UNICODE)

_IGNORE_INSTRUCTIONS_RE = re.compile(
    r"\b(?:ignore|disregard|forget|bypass|override)\b.{0,48}"
    r"\b(?:previous|prior|earlier|all|your)\b.{0,32}\b(?:instructions?|rules?|directives?)\b",
    re.IGNORECASE | re.DOTALL,
)
_PROMPT_DISCLOSURE_RE = re.compile(
    r"\b(?:reveal|show|print|expose|repeat|leak)\b.{0,48}"
    r"\b(?:system|developer)\s+prompt\b|\b(?:system|developer)\s+prompt\b.{0,48}"
    r"\b(?:reveal|show|print|expose|repeat|leak)\b",
    re.IGNORECASE | re.DOTALL,
)
_ROLE_OVERRIDE_RE = re.compile(
    r"\b(?:you are now|act as|pretend to be|assume the role|new authority|highest priority|"
    r"override (?:your )?(?:role|authority|policy|rules?))\b",
    re.IGNORECASE,
)

_IMPERATIVE_RE = re.compile(
    r"(?:^|[.!?]\s+|\bplease\s+|\byou (?:must|should|need to)\s+)"
    r"(?:run|execute|launch|invoke|open)\b|\b(?:in|using) (?:a |your )?(?:shell|terminal)\b",
    re.IGNORECASE,
)
_COMMAND_TOOL_RE = re.compile(
    r"(?:^|[\s`|;&])(?:curl|wget|pip(?:3)?|npm|npx|chmod|bash|sh)(?=$|[\s`|;&-])",
    re.IGNORECASE,
)
_DANGEROUS_PIPE_RE = re.compile(
    r"\b(?:curl|wget)\b.{0,160}(?:\||&&|;)\s*(?:sudo\s+)?(?:bash|sh)\b|"
    r"\bchmod\s+\+x\b",
    re.IGNORECASE | re.DOTALL,
)

_SECRET_RE = re.compile(
    r"\b(?:seed phrase|recovery phrase|mnemonic(?: phrase)?|private key|"
    r"api (?:token|key)|access token)\b",
    re.IGNORECASE,
)
_SOLICIT_RE = re.compile(
    r"\b(?:send|share|reveal|provide|enter|paste|upload|submit|give|verify)\b",
    re.IGNORECASE,
)
_PROTECTIVE_SECRET_RE = re.compile(
    r"\b(?:never|do not|don't|should not|shouldn't)\s+(?:send|share|reveal|provide|enter|paste|upload|submit|give)\b",
    re.IGNORECASE,
)
_WALLET_ACTION_RE = re.compile(
    r"\b(?:connect|link|sync|verify)\s+(?:your\s+)?wallet\b|"
    r"\bsign\s+(?:this\s+|the\s+|a\s+)?transaction\b",
    re.IGNORECASE,
)

_URL_ACTION_RE = re.compile(
    r"\b(?:act now|authorize|claim|click|connect|download|install|link|login|log in|"
    r"open|redeem|register|sign|submit|verify|visit)\b",
    re.IGNORECASE,
)
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

_FORMULAIC_FARMING_RE = re.compile(
    r"\b(?:daily\s+)?(?:presence|check[ -]?in)\b.{0,48}\b(?:present|ready|flop)\b|"
    r"\b(?:present|here)\s+and\s+ready\s+for\s+flop\b|"
    r"\bready\s+for\s+flop\b",
    re.IGNORECASE | re.DOTALL,
)


def _excerpt(text: str) -> str:
    """Make display-only text safe, compact, URL-redacted, and bounded."""

    redacted = _URL_RE.sub("[url]", text)
    cleaned = "".join(
        " "
        if unicodedata.category(character) in {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}
        else character
        for character in redacted
    )
    collapsed = " ".join(cleaned.split())
    if len(collapsed) <= 160:
        return collapsed
    return collapsed[:157].rstrip() + "..."


def _url_has_literal_risky_host(url: str) -> bool:
    """Inspect a URL lexically; this never performs DNS or any other I/O."""

    try:
        host = urlsplit(url).hostname
        if host is None:
            return False
        address = ipaddress.ip_address(host)
    except (ValueError, UnicodeError):
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or any(address in network for network in _DOCUMENTATION_NETWORKS)
    )


def _repetition_rule(text: str) -> str | None:
    words = [word.casefold() for word in _WORD_RE.findall(text)]
    if len(words) < 8:
        return None

    counts = Counter(words)
    token, count = counts.most_common(1)[0]
    if len(token) >= 4 and count >= 8 and count / len(words) >= 0.4:
        return "heuristic: strongly repeated token"

    # Phrase repetition is checked on normalized tokens, so punctuation and
    # whitespace differences do not change the deterministic result.
    for width in range(min(12, len(words) // 4), 2, -1):
        phrases = Counter(tuple(words[index : index + width]) for index in range(len(words) - width + 1))
        if phrases and phrases.most_common(1)[0][1] >= 4:
            return "heuristic: strongly repeated phrase"
    return None


def scan_text(text: str) -> tuple[Finding, ...]:
    """Return deterministic findings for *text* without performing any I/O."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")

    excerpt = _excerpt(text)
    findings: list[Finding] = []

    if _IGNORE_INSTRUCTIONS_RE.search(text):
        findings.append(Finding(ScanCategory.PROMPT_INJECTION, Severity.HIGH, "ignore prior instructions", excerpt))
    elif _PROMPT_DISCLOSURE_RE.search(text):
        findings.append(Finding(ScanCategory.PROMPT_INJECTION, Severity.HIGH, "system/developer prompt disclosure", excerpt))
    elif _ROLE_OVERRIDE_RE.search(text):
        findings.append(Finding(ScanCategory.PROMPT_INJECTION, Severity.MEDIUM, "role or authority override", excerpt))

    if _DANGEROUS_PIPE_RE.search(text):
        findings.append(Finding(ScanCategory.COMMAND_EXECUTION, Severity.HIGH, "download/permission shell execution pattern", excerpt))
    elif _IMPERATIVE_RE.search(text) and _COMMAND_TOOL_RE.search(text):
        findings.append(Finding(ScanCategory.COMMAND_EXECUTION, Severity.HIGH, "imperative shell command with executable tool", excerpt))

    wallet_action = _WALLET_ACTION_RE.search(text)
    secret = _SECRET_RE.search(text)
    solicitation = _SOLICIT_RE.search(text)
    protective = _PROTECTIVE_SECRET_RE.search(text)
    if wallet_action:
        findings.append(Finding(ScanCategory.WALLET_SECRET_SOLICITATION, Severity.HIGH, "wallet connection or transaction-signing request", excerpt))
    elif secret and solicitation and not protective:
        findings.append(Finding(ScanCategory.WALLET_SECRET_SOLICITATION, Severity.HIGH, "secret credential solicitation", excerpt))

    urls = _URL_RE.findall(text)
    if urls:
        if any(_url_has_literal_risky_host(url.rstrip(".,);]")) for url in urls):
            findings.append(Finding(ScanCategory.SUSPICIOUS_URL, Severity.HIGH, "literal private, loopback, or documentation IP URL", excerpt))
        elif _URL_ACTION_RE.search(text):
            findings.append(Finding(ScanCategory.SUSPICIOUS_URL, Severity.MEDIUM, "URL paired with action or authorization language", excerpt))

    farming_rule = (
        "heuristic: formulaic presence/check-in/ready-for-FLOP pattern"
        if _FORMULAIC_FARMING_RE.search(text)
        else _repetition_rule(text)
    )
    if farming_rule:
        findings.append(Finding(ScanCategory.REPETITIVE_FARMING, Severity.LOW, farming_rule, excerpt))

    return tuple(findings)


def _is_signed(message: Mapping[str, object]) -> bool:
    explicit = message.get("signed")
    if explicit is True:
        return True
    if any(isinstance(message.get(field), str) and bool(message[field]) for field in ("signature", "sig")):
        return True
    sender = message.get("from")
    nonce = message.get("nonce")
    return (
        isinstance(sender, str)
        and sender.startswith("did:key:z6Mk")
        and isinstance(nonce, int)
        and not isinstance(nonce, bool)
        and nonce >= 0
    )


def scan_room_payload(payload: object) -> dict[str, object]:
    """Validate and summarize a Technocore JSON room response.

    Validation is intentionally shallow: only the top-level response and each
    message record are inspected.  Unknown nested content is neither traversed
    nor interpreted.
    """

    if not isinstance(payload, Mapping):
        raise ValueError("room payload must be a mapping")
    room = payload.get("room")
    messages = payload.get("messages")
    if not isinstance(room, str) or not room.strip() or len(room) > 256:
        raise ValueError("room must be a non-empty string of at most 256 characters")
    if not isinstance(messages, list):
        raise ValueError("messages must be a list")
    if len(messages) > 200:
        raise ValueError("messages must contain at most 200 entries")

    category_counts = {category.value: 0 for category in ScanCategory}
    severity_counts = {severity.value: 0 for severity in Severity}
    examples: dict[str, list[dict[str, object]]] = {category.value: [] for category in ScanCategory}
    sequences: list[int] = []
    signed_count = 0

    for index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            raise ValueError(f"message {index} must be a mapping")
        seq = message.get("seq")
        sender = message.get("from")
        text = message.get("text")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ValueError(f"message {index} seq must be a non-negative integer")
        if not isinstance(sender, str) or not sender.strip() or len(sender) > 256:
            raise ValueError(f"message {index} from must be a non-empty string of at most 256 characters")
        if not isinstance(text, str) or len(text) > 100_000:
            raise ValueError(f"message {index} text must be a string of at most 100000 characters")
        if "signed" in message and not isinstance(message["signed"], bool):
            raise ValueError(f"message {index} signed must be a boolean when present")

        sequences.append(seq)
        if _is_signed(message):
            signed_count += 1

        for finding in scan_text(text):
            category = finding.category.value
            category_counts[category] += 1
            severity_counts[finding.severity.value] += 1
            if len(examples[category]) < 3:
                examples[category].append(
                    {
                        "seq": seq,
                        "from": sender,
                        "severity": finding.severity.value,
                        "rule": finding.rule,
                        "excerpt": finding.excerpt,
                    }
                )

    return {
        "room": room,
        "first_seq": min(sequences) if sequences else None,
        "last_seq": max(sequences) if sequences else None,
        "scanned_count": len(messages),
        "signed_count": signed_count,
        "unsigned_count": len(messages) - signed_count,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "examples": examples,
    }
