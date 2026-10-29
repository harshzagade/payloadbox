# PayloadBox

Encoder/decoder chains for payloads — a daily-driver CLI for red teamers and
web testers. Chain URL, double-URL, HTML entity, unicode-escape, hex,
hex-escape, octal-escape and base64 codecs in any order, or ask PayloadBox
what encoding a blob looks like.

Stdlib-only. No dependencies, no network calls.

## Install

```bash
git clone https://github.com/harshzagade/payloadbox
cd payloadbox
pip install .
# or run without installing:
python -m payloadbox --version
```

Requires Python 3.8+.

## Usage

```
payloadbox encode [-c CHAIN] [TEXT]     # encode through a codec chain
payloadbox decode [-c CHAIN] [TEXT]     # decode (chain undone in reverse)
payloadbox list                         # show available codecs
payloadbox detect [TEXT]                # guess which encodings are present
```

Input can be the TEXT argument, `--input-file`, or piped stdin. Output goes to
stdout or `--output-file`.

### Codecs

```
url        Percent-encoding (%3C)
url2       Double percent-encoding (%253C)
html       HTML entities (&lt;)
uni        Unicode escapes (\u003c)
hex        Hex string (3c)
hexesc     Hex escapes (\x3c)
oct        Octal escapes (\074)
base64     Base64 (standard, padded)
base64url  Base64 URL-safe (unpadded)
```

### Examples

Chain encodings for a WAF-bypass test — `decode` undoes the same chain in
reverse, so the two commands are inverses:

```bash
$ payloadbox encode -c url,base64 "<script>alert(1)</script>"
JTNDc2NyaXB0JTNFYWxlcnQlMjgxJTI5JTNDJTJGc2NyaXB0JTNF

$ payloadbox decode -c url,base64 "JTNDc2NyaXB0JTNFYWxlcnQlMjgxJTI5JTNDJTJGc2NyaXB0JTNF"
<script>alert(1)</script>
```

Unicode-escape an event-handler payload:

```bash
$ payloadbox encode -c uni "<img src=x onerror=alert(1)>"
\u003c\u0069\u006d\u0067\u0020\u0073\u0072\u0063\u003d\u0078\u0020\u006f\u006e\u0065\u0072\u0072\u006f\u0072\u003d\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029\u003e
```

Identify an unknown blob:

```bash
$ payloadbox detect "%253Cscript%253E"
url2  contains double-encoded sequences like %253C
url   contains percent-encoded sequences like %3C

$ payloadbox detect "aGVsbG8="
base64  base64 alphabet with padding or +/
```

Pipe-friendly:

```bash
$ echo -n "AB" | payloadbox encode -c hex
4142
```

## Tests

```bash
python -m unittest discover -s tests -v
```

30 tests: known vectors per codec, round-trips (including unicode and empty
input), chain inversion, and detector heuristics.

## License

MIT — see [LICENSE](LICENSE).
