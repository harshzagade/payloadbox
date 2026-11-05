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
payloadbox encode [-c CHAIN] [--rot N] [TEXT]  # encode through a codec chain
payloadbox decode [-c CHAIN] [--rot N] [TEXT]  # decode (chain undone in reverse)
payloadbox decode --auto [TEXT]                # detect + decode until plain text
payloadbox list                                # show available codecs
payloadbox detect [--json] [TEXT]              # guess which encodings are present
```

`detect --json` prints a machine-readable list of detected encodings with
their evidence strings (an empty list when nothing is detected), for
pipeline consumers:

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
rot13      ROT13 Caesar shift
utf16le    UTF-16LE bytes, latin-1 mapped (BOM tolerated)
utf16be    UTF-16BE bytes, latin-1 mapped (BOM tolerated)
qp         Quoted-printable (=XX, MIME/email-header)
jwt        JWT header/payload decode only (signature never verified)
```

`jwt` is decode-only: `encode -c jwt` fails with a clear error, since
there is no plain-text form to encode to and the signature is never
verified against any key.

Any Caesar shift is available as a chain step too: `rot1` … `rot25`
(`rot13` is the registered name; `rotN` for other shifts is resolved
dynamically). `--rot N` is shorthand for appending `rotN` to the chain, or
for using it alone when `-c` is omitted.

### Examples

Chain encodings for a WAF-bypass test — `decode` undoes the same chain in
reverse, so the two commands are inverses:

```bash
$ payloadbox encode -c url,base64 "<script>alert(1)</script>"
JTNDc2NyaXB0JTNFYWxlcnQlMjgxJTI5JTNDJTJGc2NyaXB0JTNF

$ payloadbox decode -c url,base64 "JTNDc2NyaXB0JTNFYWxlcnQlMjgxJTI5JTNDJTJGc2NyaXB0JTNF"
<script>alert(1)</script>
```

Add a classic Caesar layer to a WAF-bypass chain:

```bash
$ payloadbox encode --rot 13 "<script>"
<fpevcg>

$ payloadbox encode -c url,rot5 "<script>"
%3Hxhwnuy%3J

$ payloadbox encode -c base64 --rot 1 "hello"
bHWtcH8=
```

UTF-16 encode a payload (a common filter-bypass layer — raw bytes are
carried as latin-1 characters so they pipe cleanly; decode tolerates a
leading BOM):

```bash
$ payloadbox encode -c utf16le "hi" | od -An -tx1
 68 00 69 00 0a

$ printf 'h\0i\0' | payloadbox decode -c utf16le
hi
```

Decode a JWT's header and payload into readable JSON (decode only — the
signature segment is ignored, never verified):

```bash
$ payloadbox decode -c jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
  }
}
```

Quoted-printable encode an email-header payload (non-ASCII bytes become
`=XX`, plain ASCII passes through):

```bash
$ payloadbox encode -c qp "café <b>"
caf=C3=A9 <b>

$ payloadbox decode -c qp "caf=C3=A9 <b>"
café <b>
```

Unicode-escape an event-handler payload:

```bash
$ payloadbox encode -c uni "<img src=x onerror=alert(1)>"
\u003c\u0069\u006d\u0067\u0020\u0073\u0072\u0063\u003d\u0078\u0020\u006f\u006e\u0065\u0072\u0072\u006f\u0072\u003d\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029\u003e
```

Fully decode an unknown blob without naming the layers — `decode --auto`
detects and peels one layer at a time until plain text, stopping on
already-plain input, undecodable blobs, repeated results, or 20 steps
(the chain used is reported on stderr, so stdout stays pipeable):

```bash
$ payloadbox decode --auto "%253Cscript%253E"
<script>

$ payloadbox decode --auto "JTNDc2NyaXB0JTNF"
<script>
```

Identify an unknown blob:

```bash
$ payloadbox detect "%253Cscript%253E"
url2  contains double-encoded sequences like %253C
url   contains percent-encoded sequences like %3C

$ payloadbox detect "aGVsbG8="
base64  base64 alphabet with padding or +/

$ payloadbox detect --json "aGVsbG8="
[
  {
    "encoding": "base64",
    "evidence": "base64 alphabet with padding or +/"
  }
]
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

53 tests: known vectors per codec, round-trips (including unicode and empty
input), chain inversion, detector heuristics, JWT decode-only behaviour,
and machine-readable `detect --json` output.

## License

MIT — see [LICENSE](LICENSE).
