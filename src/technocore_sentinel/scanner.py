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
from typing import cast
import unicodedata
from urllib.parse import urlsplit


class ScanCategory(str, Enum):
    """Stable public categories emitted by :func:`scan_text`."""

    PROMPT_INJECTION = "prompt_injection"
    COMMAND_EXECUTION = "command_execution"
    WALLET_SECRET_SOLICITATION = "wallet_secret_solicitation"
    IMPERSONATION = "impersonation"
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
_CLAUSE_BOUNDARY_RE = re.compile(
    r"[.!?;\r\n]+|"
    r"(?:,\s*)?\b(?:but|however|instead|yet|nevertheless|nonetheless)\b[,:]?|"
    r",\s*(?=(?:now|then)\b)",
    re.IGNORECASE,
)
_BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58BTC_VALUES = {character: value for value, character in enumerate(_BASE58BTC_ALPHABET)}
_ED25519_DID_PREFIX = "did:key:z"
_ED25519_MULTICODEC = b"\xed\x01"
# A 64-byte signature has 86 unpadded base64url characters.  Its final
# character contains only two data bits, so canonical encodings end as below.
_LEGACY_SIGNATURE_RE = re.compile(r"[A-Za-z0-9_-]{85}[AQgw]\Z")
_MAX_NONCE = 9_999_999_999_999_999_999
# Technocore rooms contain at most 200 messages of at most 4096 text
# characters each.  Bound total regex/sanitization work even when an
# upstream or adversarial payload uses the scanner's larger per-field guard.
MAX_AGGREGATE_TEXT_CHARACTERS = 200 * 4096

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
_PROTECTIVE_WALLET_RE = re.compile(
    r"\b(?:never|do not|don't|should not|shouldn't)\b.{0,48}"
    r"(?:\b(?:connect|link|sync|verify)\s+(?:your\s+)?wallet\b|"
    r"\bsign\s+(?:this\s+|the\s+|a\s+)?transaction\b)",
    re.IGNORECASE,
)

_CLAIMED_OFFICIAL_IDENTITY_RE = re.compile(
    r"\b(?:i am|i'm|this is|we are|speaking as)\b.{0,40}"
    r"\b(?:official|admin(?:istrator)?|moderator|support|staff|representative)\b",
    re.IGNORECASE,
)
_IDENTITY_TRUST_CUE_RE = re.compile(
    r"\b(?:trust me|you can trust|verified|legitimate|authentic|"
    r"contact me|message me|direct message|dm me|reach me|reply privately|"
    r"new account|backup account|alternate account|temporary account|"
    r"switched accounts|lost access|account (?:was )?hacked)\b",
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


def _sanitize_display(text: str) -> str:
    """Make untrusted display text safe, compact, URL-redacted, and bounded."""

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

    excerpt = _sanitize_display(text)
    findings: list[Finding] = []
    # Protective advice only suppresses requests in the same local clause.
    # Adversative transitions explicitly start a new clause so an attacker
    # cannot negate an initial warning and hide a later solicitation behind it.
    clauses = tuple(clause for clause in _CLAUSE_BOUNDARY_RE.split(text) if clause.strip())

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

    wallet_request = any(
        _WALLET_ACTION_RE.search(clause)
        and not _PROTECTIVE_WALLET_RE.search(clause)
        for clause in clauses
    )
    secret_request = any(
        _SECRET_RE.search(clause)
        and _SOLICIT_RE.search(clause)
        and not _PROTECTIVE_SECRET_RE.search(clause)
        for clause in clauses
    )
    if wallet_request:
        findings.append(Finding(ScanCategory.WALLET_SECRET_SOLICITATION, Severity.HIGH, "wallet connection or transaction-signing request", excerpt))
    elif secret_request:
        findings.append(Finding(ScanCategory.WALLET_SECRET_SOLICITATION, Severity.HIGH, "secret credential solicitation", excerpt))

    if _CLAIMED_OFFICIAL_IDENTITY_RE.search(text) and _IDENTITY_TRUST_CUE_RE.search(text):
        findings.append(
            Finding(
                ScanCategory.IMPERSONATION,
                Severity.MEDIUM,
                "heuristic: claimed official/admin identity paired with trust, contact, or account-switch cue",
                excerpt,
            )
        )

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


def _is_ed25519_did(sender: str) -> bool:
    """Strictly decode and validate a Base58btc Ed25519 ``did:key`` marker."""

    if not sender.startswith(_ED25519_DID_PREFIX):
        return False
    fingerprint = sender[len(_ED25519_DID_PREFIX) :]
    if not fingerprint:
        return False

    value = 0
    try:
        for character in fingerprint:
            value = value * 58 + _BASE58BTC_VALUES[character]
    except KeyError:
        return False

    leading_zeroes = len(fingerprint) - len(fingerprint.lstrip("1"))
    decoded_body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    decoded = b"\x00" * leading_zeroes + decoded_body
    return len(decoded) == 34 and decoded[:2] == _ED25519_MULTICODEC


def _is_signed(message: Mapping[str, object]) -> bool:
    explicit = message.get("signed")
    # An explicit negative marker always wins over inferred live or legacy
    # markers.  A positive boolean alone is not cryptographic evidence.
    if explicit is False:
        return False

    sender = message.get("from")
    nonce = message.get("nonce")
    valid_live_marker = (
        isinstance(sender, str)
        and _is_ed25519_did(sender)
        and isinstance(nonce, int)
        and not isinstance(nonce, bool)
        and 1 <= nonce <= _MAX_NONCE
    )
    if valid_live_marker:
        return True

    return any(
        isinstance(signature := message.get(field), str)
        and _LEGACY_SIGNATURE_RE.fullmatch(signature) is not None
        for field in ("signature", "sig")
    )


def sanitize_display(text: str) -> str:
    """Return the scanner's bounded, URL-redacted form of display text."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    return _sanitize_display(text)


def is_message_signed(message: Mapping[str, object]) -> bool:
    """Return whether *message* exposes a recognized server signed marker.

    This recognizes live/legacy marker shapes for reporting.  It does not
    independently verify a live message's cryptographic signature.
    """

    return _is_signed(message)


def validate_room_payload(
    payload: object,
) -> tuple[str, tuple[Mapping[str, object], ...]]:
    """Validate a room payload without scanning message text.

    Validation is shallow and applies the same message-count and aggregate-text
    bounds as :func:`scan_room_payload`.  Message sequences must be positive and
    strictly increasing.  Optional server metadata is checked against the
    ordered records before any sanitization.  For an empty response, ``last_seq``
    is a non-negative cursor echo when present.  The returned room name is
    sanitized; message mappings remain read-only inputs for callers to scan.
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
    if "count" in payload:
        count = payload["count"]
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            or count != len(messages)
        ):
            raise ValueError("count must be a non-negative integer equal to len(messages)")

    aggregate_text_characters = 0
    validated_messages: list[Mapping[str, object]] = []
    previous_message_seq = 0
    for index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            raise ValueError(f"message {index} must be a mapping")
        seq = message.get("seq")
        sender = message.get("from")
        text = message.get("text")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
            raise ValueError(f"message {index} seq must be a positive integer")
        if seq <= previous_message_seq:
            raise ValueError("message seq values must be strictly increasing")
        if not isinstance(sender, str) or not sender.strip() or len(sender) > 256:
            raise ValueError(f"message {index} from must be a non-empty string of at most 256 characters")
        if not isinstance(text, str) or len(text) > 100_000:
            raise ValueError(f"message {index} text must be a string of at most 100000 characters")
        if "signed" in message and not isinstance(message["signed"], bool):
            raise ValueError(f"message {index} signed must be a boolean when present")

        aggregate_text_characters += len(text)
        if aggregate_text_characters > MAX_AGGREGATE_TEXT_CHARACTERS:
            raise ValueError(
                "messages aggregate text must contain at most "
                f"{MAX_AGGREGATE_TEXT_CHARACTERS} characters"
            )
        validated_messages.append(message)
        previous_message_seq = seq

    if validated_messages:
        expected_first_seq = cast(int, validated_messages[0]["seq"])
        expected_last_seq = cast(int, validated_messages[-1]["seq"])
        for field, expected in (
            ("first_seq", expected_first_seq),
            ("last_seq", expected_last_seq),
        ):
            if field in payload:
                value = payload[field]
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value <= 0
                    or value != expected
                ):
                    raise ValueError(
                        f"{field} must be a positive integer equal to the ordered {field} message"
                    )
    else:
        if "first_seq" in payload and payload["first_seq"] is not None:
            raise ValueError("first_seq must be None when messages is empty")
        if "last_seq" in payload:
            last_seq = payload["last_seq"]
            if (
                isinstance(last_seq, bool)
                or not isinstance(last_seq, int)
                or last_seq < 0
            ):
                raise ValueError(
                    "last_seq must be a non-negative integer cursor when messages is empty"
                )

    # Do no sanitization until every accepted message has passed shallow
    # validation and the aggregate text budget is known safe.
    sanitized_room = _sanitize_display(room)
    if not sanitized_room:
        raise ValueError("room must contain displayable characters")
    for index, message in enumerate(validated_messages):
        if not _sanitize_display(cast(str, message["from"])):
            raise ValueError(f"message {index} from must contain displayable characters")

    return sanitized_room, tuple(validated_messages)


def scan_room_payload(payload: object) -> dict[str, object]:
    """Validate and summarize a Technocore JSON room response.

    Validation is intentionally shallow: only the top-level response and each
    message record are inspected.  Unknown nested content is neither traversed
    nor interpreted.
    """

    sanitized_room, messages = validate_room_payload(payload)

    category_counts = {category.value: 0 for category in ScanCategory}
    severity_counts = {severity.value: 0 for severity in Severity}
    examples: dict[str, list[dict[str, object]]] = {category.value: [] for category in ScanCategory}
    sequences: list[int] = []
    signed_count = 0

    for message in messages:
        seq = cast(int, message.get("seq"))
        sender = cast(str, message.get("from"))
        text = cast(str, message.get("text"))
        sanitized_sender = _sanitize_display(sender)

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
                        "from": sanitized_sender,
                        "severity": finding.severity.value,
                        "rule": finding.rule,
                        "excerpt": finding.excerpt,
                    }
                )

    return {
        "room": sanitized_room,
        "first_seq": sequences[0] if sequences else None,
        "last_seq": sequences[-1] if sequences else None,
        "scanned_count": len(messages),
        "signed_count": signed_count,
        "unsigned_count": len(messages) - signed_count,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "examples": examples,
    }
