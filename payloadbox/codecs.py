"""Encoder/decoder registry for PayloadBox.

Every codec exposes ``encode`` and ``decode`` over ``str``. Byte-oriented
codecs operate on the UTF-8 representation of the input.
"""
from __future__ import annotations

import base64
import html
import re
import urllib.parse
from dataclasses import dataclass
from typing import Callable


def _to_bytes(s: str) -> bytes:
    return s.encode("utf-8")


def _from_bytes(b: bytes) -> str:
    return b.decode("utf-8")


# ---------------------------------------------------------------- url ------
def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def url_decode(s: str) -> str:
    return urllib.parse.unquote(s)


# ------------------------------------------------------------ url2 ---------
def url2_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def url2_decode(s: str) -> str:
    return urllib.parse.unquote(urllib.parse.unquote(s))


# ------------------------------------------------------------ html ---------
def html_encode(s: str) -> str:
    return html.escape(s, quote=True)


def html_decode(s: str) -> str:
    return html.unescape(s)


# ------------------------------------------------------------ uni ----------
_UNI_RE = re.compile(r"\\u([0-9A-Fa-f]{4})")


def uni_encode(s: str) -> str:
    """Encode every char as \\uXXXX (surrogate pairs for astral chars)."""
    out: list[str] = []
    for ch in s:
        o = ord(ch)
        if o < 0x10000:
            out.append(f"\\u{o:04x}")
        else:
            o -= 0x10000
            out.append(f"\\u{0xD800 + (o >> 10):04x}\\u{0xDC00 + (o & 0x3FF):04x}")
    return "".join(out)


def uni_decode(s: str) -> str:
    def repl(m: re.Match) -> str:
        return chr(int(m.group(1), 16))

    s2 = _UNI_RE.sub(repl, s)
    try:
        return s2.encode("utf-16", "surrogatepass").decode("utf-16")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return s2


# ------------------------------------------------------------ hex ----------
def hex_encode(s: str) -> str:
    return _to_bytes(s).hex()


def hex_decode(s: str) -> str:
    t = s.strip()
    if t[:2].lower() == "0x":
        t = t[2:]
    t = re.sub(r"\s+", "", t)
    if not t:
        return ""
    if len(t) % 2:
        raise ValueError("odd-length hex string")
    return _from_bytes(bytes.fromhex(t))


# -------------------------------------------------------- hexesc ---------
_HEXESC_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")


def hexesc_encode(s: str) -> str:
    return "".join(f"\\x{b:02x}" for b in _to_bytes(s))


def hexesc_decode(s: str) -> str:
    out = bytearray()
    i = 0
    for m in _HEXESC_RE.finditer(s):
        if m.start() > i:
            out.extend(s[i : m.start()].encode("utf-8", "surrogatepass"))
        out.append(int(m.group(1), 16))
        i = m.end()
    out.extend(s[i:].encode("utf-8", "surrogatepass"))
    return out.decode("utf-8")


# ------------------------------------------------------------ oct ----------
_OCT_RE = re.compile(r"\\([0-7]{1,3})")


def oct_encode(s: str) -> str:
    return "".join(f"\\{b:03o}" for b in _to_bytes(s))


def oct_decode(s: str) -> str:
    out = bytearray()
    i = 0
    for m in _OCT_RE.finditer(s):
        if m.start() > i:
            out.extend(s[i : m.start()].encode("utf-8", "surrogatepass"))
        out.append(int(m.group(1), 8))
        i = m.end()
    out.extend(s[i:].encode("utf-8", "surrogatepass"))
    return out.decode("utf-8")


# ---------------------------------------------------------- base64 ---------
def base64_encode(s: str) -> str:
    return base64.b64encode(_to_bytes(s)).decode("ascii")


def base64_decode(s: str) -> str:
    t = re.sub(r"\s+", "", s)
    if not t:
        return ""
    t += "=" * (-len(t) % 4)
    return _from_bytes(base64.b64decode(t, validate=True))


def base64url_encode(s: str) -> str:
    return base64.urlsafe_b64encode(_to_bytes(s)).decode("ascii").rstrip("=")


def base64url_decode(s: str) -> str:
    t = re.sub(r"\s+", "", s)
    if not t:
        return ""
    t += "=" * (-len(t) % 4)
    return _from_bytes(base64.urlsafe_b64decode(t))


# -------------------------------------------------------- registry -------
@dataclass(frozen=True)
class Codec:
    name: str
    description: str
    encode: Callable[[str], str]
    decode: Callable[[str], str]


CODECS: dict[str, Codec] = {
    c.name: c
    for c in (
        Codec("url", "Percent-encoding (%3C)", url_encode, url_decode),
        Codec("url2", "Double percent-encoding (%253C)", url2_encode, url2_decode),
        Codec("html", "HTML entities (&lt;)", html_encode, html_decode),
        Codec("uni", r"Unicode escapes (\u003c)", uni_encode, uni_decode),
        Codec("hex", "Hex string (3c)", hex_encode, hex_decode),
        Codec("hexesc", r"Hex escapes (\x3c)", hexesc_encode, hexesc_decode),
        Codec("oct", r"Octal escapes (\074)", oct_encode, oct_decode),
        Codec("base64", "Base64 (standard, padded)", base64_encode, base64_decode),
        Codec(
            "base64url",
            "Base64 URL-safe (unpadded)",
            base64url_encode,
            base64url_decode,
        ),
    )
}


def apply_chain(text: str, chain: str, mode: str) -> str:
    """Apply a comma-separated codec chain.

    ``encode`` applies codecs left to right; ``decode`` applies them in
    reverse so ``decode`` inverts ``encode`` for the same chain string.
    """
    if mode not in ("encode", "decode"):
        raise ValueError("mode must be 'encode' or 'decode'")
    names = [c.strip().lower() for c in chain.split(",") if c.strip()]
    unknown = [n for n in names if n not in CODECS]
    if unknown:
        raise KeyError(f"unknown codec(s): {', '.join(unknown)}")
    seq = names if mode == "encode" else list(reversed(names))
    for name in seq:
        codec = CODECS[name]
        text = codec.encode(text) if mode == "encode" else codec.decode(text)
    return text


# -------------------------------------------------------- detect ---------
_B64_RE = re.compile(r"^[A-Za-z0-9+/]{4,}={0,2}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9\-_]+$")


def detect(text: str) -> list[tuple[str, str]]:
    """Heuristically list encodings the text looks like. Never raises."""
    t = text.strip()
    hits: list[tuple[str, str]] = []
    if not t:
        return hits
    if re.search(r"%25[0-9A-Fa-f]{2}", t):
        hits.append(("url2", "contains double-encoded sequences like %253C"))
    if re.search(r"%[0-9A-Fa-f]{2}", t):
        hits.append(("url", "contains percent-encoded sequences like %3C"))
    if re.search(r"&(#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);", t):
        hits.append(("html", "contains HTML entities like &lt;"))
    if re.search(r"\\u[0-9A-Fa-f]{4}", t):
        hits.append(("uni", r"contains \uXXXX escapes"))
    if re.search(r"\\x[0-9A-Fa-f]{2}", t):
        hits.append(("hexesc", r"contains \xHH escapes"))
    if re.search(r"\\[0-7]{1,3}", t):
        hits.append(("oct", r"contains \OOO octal escapes"))
    if re.fullmatch(r"[0-9A-Fa-f]+", t) and len(t) % 2 == 0 and len(t) >= 4:
        hits.append(("hex", "even-length hex-only string"))
    if _B64_RE.match(t) and len(t) % 4 == 0:
        if "+" in t or "/" in t or t.endswith("="):
            hits.append(("base64", "base64 alphabet with padding or +/"))
        else:
            hits.append(("base64/base64url", "ambiguous: valid in both alphabets"))
    elif _B64URL_RE.match(t) and ("-" in t or "_" in t) and len(t) >= 4:
        hits.append(("base64url", "contains URL-safe - or _ characters"))
    return hits
