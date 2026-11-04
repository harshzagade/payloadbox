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


# ------------------------------------------------------------ rot ----------
_ROT_RE = re.compile(r"^rot(\d+)$")


def caesar_shift(s: str, shift: int) -> str:
    """Shift ASCII letters by ``shift`` (mod 26); other chars untouched."""
    shift %= 26
    out: list[str] = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def rot13_encode(s: str) -> str:
    return caesar_shift(s, 13)


def rot13_decode(s: str) -> str:
    return caesar_shift(s, 13)  # ROT13 is its own inverse


def make_rot_codec(shift: int) -> Codec:
    """Build the Codec for a ``rotN`` chain name (0 <= N <= 25)."""
    if not 0 <= shift <= 25:
        raise ValueError(f"rot shift must be 0-25, got {shift}")
    return Codec(
        f"rot{shift}",
        f"Caesar shift by {shift} (ROT{shift})",
        lambda s, n=shift: caesar_shift(s, n),
        lambda s, n=shift: caesar_shift(s, -n),
    )


# ---------------------------------------------------------- utf16 --------
def _utf16_encode(s: str, endian: str) -> str:
    """Encode to raw UTF-16 bytes, carried through the str layer via latin-1.

    Latin-1 maps bytes 1:1 to chars, so the result stays a plain str that
    pipes cleanly and round-trips exactly (surrogate pairs included).
    """
    return s.encode(f"utf-16-{endian}").decode("latin-1")


def _utf16_decode(s: str, endian: str) -> str:
    """Decode latin-1-mapped UTF-16 bytes, tolerating one leading BOM.

    A BOM is stripped whether it arrives as raw BOM bytes (``\\xff\\xfe`` /
    ``\\xfe\\xff``) or as a pasted U+FEFF character. Note the trade-off: a
    literal leading U+FEFF in the original text is not round-trip
    preserved, since its encoding is indistinguishable from a BOM.
    """
    if s.startswith("\ufeff"):
        s = s[1:]
    b = s.encode("latin-1")  # ValueError on non-latin-1 input
    bom = b"\xff\xfe" if endian == "le" else b"\xfe\xff"
    if b.startswith(bom):
        b = b[len(bom):]
    return b.decode(f"utf-16-{endian}")


def utf16le_encode(s: str) -> str:
    return _utf16_encode(s, "le")


def utf16le_decode(s: str) -> str:
    return _utf16_decode(s, "le")


def utf16be_encode(s: str) -> str:
    return _utf16_encode(s, "be")


def utf16be_decode(s: str) -> str:
    return _utf16_decode(s, "be")


def _utf16_endian(t: str) -> str | None:
    """Guess UTF-16 endianness from alternating NUL bytes, else None.

    ASCII text in UTF-16LE has NULs at odd positions, in UTF-16BE at even
    positions. Requires even length >= 4 and at least one non-NUL byte so a
    bare run of NULs is not claimed.
    """
    if len(t) < 4 or len(t) % 2:
        return None
    if all(ch == "\x00" for ch in t[1::2]) and any(ch != "\x00" for ch in t[0::2]):
        return "utf16le"
    if all(ch == "\x00" for ch in t[0::2]) and any(ch != "\x00" for ch in t[1::2]):
        return "utf16be"
    return None


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
        Codec("rot13", "ROT13 Caesar shift", rot13_encode, rot13_decode),
        Codec("utf16le", "UTF-16LE bytes, latin-1 mapped (BOM tolerated)",
              utf16le_encode, utf16le_decode),
        Codec("utf16be", "UTF-16BE bytes, latin-1 mapped (BOM tolerated)",
              utf16be_encode, utf16be_decode),
    )
}


def resolve_codec(name: str) -> Codec:
    """Look up a chain name: a registered codec, or a dynamic ``rotN``."""
    if name in CODECS:
        return CODECS[name]
    m = _ROT_RE.match(name)
    if m:
        return make_rot_codec(int(m.group(1)))
    raise KeyError(f"unknown codec(s): {name}")



def apply_chain(text: str, chain: str, mode: str) -> str:
    """Apply a comma-separated codec chain.

    ``encode`` applies codecs left to right; ``decode`` applies them in
    reverse so ``decode`` inverts ``encode`` for the same chain string.
    """
    if mode not in ("encode", "decode"):
        raise ValueError("mode must be 'encode' or 'decode'")
    names = [c.strip().lower() for c in chain.split(",") if c.strip()]
    codecs = [resolve_codec(n) for n in names]  # KeyError/ValueError on bad names
    seq = codecs if mode == "encode" else list(reversed(codecs))
    for codec in seq:
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
    endian = _utf16_endian(t)
    if endian:
        hits.append((endian, "alternating NUL bytes — looks like raw UTF-16"))
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


# -------------------------------------------------------- auto ---------
def auto_decode(text: str, max_steps: int = 20) -> tuple[str, list[str]]:
    """Repeatedly detect and decode until plain text (or a loop guard trips).

    Each step tries the detected codecs in order and takes the first one
    that decodes to something different. Stops when nothing is detected,
    when no detected codec changes the text, when a result repeats an
    earlier one (cycle guard), or after ``max_steps`` steps. Returns the
    final text and the list of codecs applied, in order.
    """
    current = text
    seen = {current}
    steps: list[str] = []
    for _ in range(max_steps):
        decoded = None
        used = None
        for name, _reason in detect(current):
            candidates = ("base64", "base64url") \
                if name == "base64/base64url" else (name,)
            for cand in candidates:
                try:
                    out = CODECS[cand].decode(current)
                except (ValueError, UnicodeDecodeError, UnicodeEncodeError):
                    continue
                if out != current:
                    decoded, used = out, cand
                    break
            if decoded is not None:
                break
        if decoded is None or decoded in seen:
            break
        seen.add(decoded)
        steps.append(used)  # type: ignore[arg-type]
        current = decoded
    return current, steps
