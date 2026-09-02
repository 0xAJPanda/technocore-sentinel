"""Shared canonical grammar for Technocore room and local names."""

from __future__ import annotations

import re

NAME_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,47}$"
_NAME_RE = re.compile(NAME_PATTERN, re.ASCII)


def is_valid_name(value: object) -> bool:
    """Return whether *value* is a canonical Technocore local name."""

    return isinstance(value, str) and _NAME_RE.fullmatch(value) is not None
