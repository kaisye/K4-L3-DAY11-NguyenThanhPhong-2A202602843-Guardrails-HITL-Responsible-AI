"""Deterministic text canonicalization used by input and output guardrails.

Security checks must inspect the same canonical representation. In particular,
Unicode compatibility characters such as full-width ``ａ`` normalize to ASCII
``a`` under NFKC. Without this layer, an output filter can miss text that a
downstream consumer later interprets as a protected value.
"""
from __future__ import annotations

import re
import unicodedata


_INVISIBLE_CATEGORIES = frozenset({"Cf", "Cc"})


def canonicalize_security_text(text: str) -> str:
    """Return an NFKC, visible and whitespace-stable security view of *text*."""
    normalized = unicodedata.normalize("NFKC", text or "")
    visible = "".join(
        char
        for char in normalized
        if unicodedata.category(char) not in _INVISIBLE_CATEGORIES
        or char in "\n\t"
    )
    return re.sub(r"[\t\r\f\v ]+", " ", visible)


def compact_security_text(text: str) -> str:
    """Return a comparison view resilient to punctuation and spacing tricks."""
    return re.sub(r"[^a-z0-9]", "", canonicalize_security_text(text).casefold())


def fold_for_matching(text: str) -> str:
    """Return lowercase accent-free text for Vietnamese keyword matching."""
    canonical = canonicalize_security_text(text).casefold().replace("đ", "d")
    decomposed = unicodedata.normalize("NFKD", canonical)
    return "".join(char for char in decomposed if unicodedata.category(char) != "Mn")


def looks_like_codepoint_decoding_request(text: str) -> bool:
    """Detect requests that ask the model to decode numeric character streams.

    Numeric encodings are not malicious by themselves. The gate therefore
    requires both a conversion instruction and a sufficiently long run of byte
    or Unicode-like integers, which avoids blocking ordinary banking amounts.
    """
    canonical = canonicalize_security_text(text).casefold()
    conversion_signal = re.search(
        r"(?:unicode|ascii|code\s*points?|scalar\s*values?|decimal|bytes?|glyphs?)"
        r".{0,100}(?:render|decode|convert|correspond|character|full[ -]?width)"
        r"|(?:render|decode|convert).{0,100}"
        r"(?:unicode|ascii|code\s*points?|scalar\s*values?|decimal|bytes?|glyphs?)",
        canonical,
        re.DOTALL,
    )
    numeric_tokens = re.findall(
        r"(?<!\d)(?:[3-9]\d|1\d{2}|2[0-4]\d|25[0-5])(?!\d)", canonical
    )
    return bool(conversion_signal and len(numeric_tokens) >= 8)
