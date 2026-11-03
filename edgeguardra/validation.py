"""Shared limits for signed messages and trusted local administration."""
from __future__ import annotations

import re
from typing import Any

MAX_TIMESTAMP = 4_102_444_800  # 2100-01-01 UTC, inclusive
MAX_TIME_TO_LIVE = 86_400
MAX_CLOCK_SKEW = 300
MAX_CONTEXT_VERSION = (1 << 63) - 1  # SQLite signed INTEGER range
# A nonce may be reconsidered after a later configuration expands the window.
# Keep old expiry records beyond the largest permitted acceptance window.
NONCE_RETENTION_MARGIN = MAX_TIME_TO_LIVE + MAX_CLOCK_SKEW
IDENT = re.compile(r'[A-Za-z0-9_.:-]{1,128}\Z')


def is_identifier(value: Any) -> bool:
    return isinstance(value,str) and IDENT.fullmatch(value) is not None


def is_timestamp(value: Any) -> bool:
    return type(value) is int and 0 <= value <= MAX_TIMESTAMP
