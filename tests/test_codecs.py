"""Tests for payloadbox.codecs — known vectors + round-trips."""
import unittest

from payloadbox.codecs import CODECS, apply_chain, auto_decode, detect


class TestKnownVectors(unittest.TestCase):
    def test_url(self):
        c = CODECS["url"]
        self.assertEqual(c.encode("<script>alert(1)</script>"),
                         "%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        self.assertEqual(c.decode("%3Cscript%3E"), "<script>")

    def test_url2(self):
        c = CODECS["url2"]
        self.assertEqual(c.encode("<"), "%253C")
        self.assertEqual(c.decode("%253C"), "<")

    def test_html(self):
        c = CODECS["html"]
        self.assertEqual(c.encode('<a href="x">&'), "&lt;a href=&quot;x&quot;&gt;&amp;")
        self.assertEqual(c.decode("&lt;&#x41;&#65;"), "<AA")

    def test_uni(self):
        c = CODECS["uni"]
        self.assertEqual(c.encode("A<"), "\\u0041\\u003c")
        self.assertEqual(c.decode("\\u0041\\u003c"), "A<")

    def test_hex(self):
        c = CODECS["hex"]
        self.assertEqual(c.encode("AB"), "4142")
        self.assertEqual(c.decode("4142"), "AB")
        self.assertEqual(c.decode("0x4142"), "AB")

    def test_hexesc(self):
        c = CODECS["hexesc"]
        self.assertEqual(c.encode("AB"), "\\x41\\x42")
        self.assertEqual(c.decode("\\x41\\x42"), "AB")

    def test_oct(self):
        c = CODECS["oct"]
        self.assertEqual(c.encode("AB"), "\\101\\102")
        self.assertEqual(c.decode("\\101\\102"), "AB")

    def test_base64(self):
        c = CODECS["base64"]
        self.assertEqual(c.encode("hello"), "aGVsbG8=")
        self.assertEqual(c.decode("aGVsbG8="), "hello")
        self.assertEqual(c.decode("aGVsbG8"), "hello")  # missing padding tolerated

    def test_base64url(self):
        c = CODECS["base64url"]
        self.assertEqual(c.encode(">>>???"), "Pj4-Pz8_")
        self.assertEqual(c.decode("Pj4-Pz8_"), ">>>???")

    def test_base32(self):
        c = CODECS["base32"]
        self.assertEqual(c.encode("hello"), "NBSWY3DP")
        self.assertEqual(c.decode("NBSWY3DP"), "hello")
        self.assertEqual(c.encode("hi"), "NBUQ====")
        self.assertEqual(c.decode("NBUQ===="), "hi")
        # missing padding, lowercase and whitespace tolerated
        self.assertEqual(c.decode("NBUQ"), "hi")
        self.assertEqual(c.decode("nbswy3dp"), "hello")
        self.assertEqual(c.decode("NBSW Y3DP"), "hello")
        self.assertEqual(c.encode(""), "")
        self.assertEqual(c.decode(""), "")
        # composes with other codecs and inverts as a chain
        original = "<script>alert(1)</script>"
        encoded = apply_chain(original, "base32,url", "encode")
        self.assertEqual(apply_chain(encoded, "base32,url", "decode"), original)
        # characters outside the A-Z2-7 alphabet are rejected
        with self.assertRaises(ValueError):
            c.decode("NBSWY3D1")
        with self.assertRaises(ValueError):
            c.decode("NBSWY3D8")

    def test_base85(self):
        c = CODECS["base85"]
        self.assertEqual(c.encode("hello"), "Xk~0{Zv")
        self.assertEqual(c.decode("Xk~0{Zv"), "hello")
        self.assertEqual(c.encode(""), "")
        self.assertEqual(c.decode(""), "")
        # whitespace tolerated
        self.assertEqual(c.decode("Xk~0 {Zv"), "hello")
        # composes with other codecs and inverts as a chain
        original = "<script>alert(1)</script>"
        encoded = apply_chain(original, "base85,url", "encode")
        self.assertEqual(apply_chain(encoded, "base85,url", "decode"), original)
        # characters outside the RFC 1924 alphabet are rejected
        with self.assertRaises(ValueError):
            c.decode('Xk~0{Z"')
        with self.assertRaises(ValueError):
            c.decode("Xk~0,Zv")

    def test_zlib(self):
        import zlib
        c = CODECS["zlib"]
        # known vector: level-9 compression of b"hello"
        self.assertEqual(c.encode("hello"),
                         zlib.compress(b"hello", 9).decode("latin-1"))
        self.assertEqual(c.decode(c.encode("hello")), "hello")
        self.assertEqual(c.encode(""), zlib.compress(b"", 9).decode("latin-1"))
        self.assertEqual(c.decode(c.encode("")), "")
        # unicode round-trips through the latin-1-mapped compressed bytes
        self.assertEqual(c.decode(c.encode("héllo 🎯")), "héllo 🎯")
        # composes with base64 for printable transport, inverts as a chain
        original = "<script>alert(1)</script>"
        encoded = apply_chain(original, "zlib,base64", "encode")
        self.assertEqual(apply_chain(encoded, "zlib,base64", "decode"), original)
        # truncated streams and non-zlib input are rejected, not garbage
        with self.assertRaises(ValueError):
            c.decode(c.encode("hello")[:-2])
        with self.assertRaises(ValueError):
            c.decode("not a zlib stream")
        with self.assertRaises(ValueError):
            c.decode("x\x9c\xff\xff")

    def test_rot13(self):
        c = CODECS["rot13"]
        self.assertEqual(c.encode("Hello, World!"), "Uryyb, Jbeyq!")
        self.assertEqual(c.decode("Uryyb, Jbeyq!"), "Hello, World!")
        self.assertEqual(c.encode("123!@#"), "123!@#")  # non-letters untouched

    def test_utf16le(self):
        c = CODECS["utf16le"]
        self.assertEqual(c.encode("AB"), "A\x00B\x00")
        self.assertEqual(c.decode("A\x00B\x00"), "AB")
        # BOM tolerated, both as raw BOM bytes and as a pasted U+FEFF
        self.assertEqual(c.decode("\xff\xfeA\x00B\x00"), "AB")
        self.assertEqual(c.decode("\ufeffA\x00B\x00"), "AB")
        # odd byte count is undecodable, not silently truncated
        with self.assertRaises(UnicodeDecodeError):
            c.decode("A\x00B")

    def test_qp(self):
        c = CODECS["qp"]
        self.assertEqual(c.encode("a b+c=d&e"), "a b+c=3Dd&e")
        self.assertEqual(c.decode("a b+c=3Dd&e"), "a b+c=d&e")
        self.assertEqual(c.encode("héllo"), "h=C3=A9llo")
        self.assertEqual(c.decode("h=C3=A9llo"), "héllo")
        # plain text and invalid escapes pass through untouched
        self.assertEqual(c.decode("hello"), "hello")
        self.assertEqual(c.decode("=ZZ"), "=ZZ")
        # soft line breaks (76-col wrap) decode back exactly
        long_text = "x" * 200
        self.assertEqual(c.decode(c.encode(long_text)), long_text)
        # composes with other codecs and inverts as a chain
        original = "<b>café</b>"
        encoded = apply_chain(original, "qp,base64", "encode")
        self.assertEqual(apply_chain(encoded, "qp,base64", "decode"), original)

    def test_utf16be(self):
        c = CODECS["utf16be"]
        self.assertEqual(c.encode("AB"), "\x00A\x00B")
        self.assertEqual(c.decode("\x00A\x00B"), "AB")
        self.assertEqual(c.decode("\xfe\xff\x00A\x00B"), "AB")
        self.assertEqual(c.decode("\ufeff\x00A\x00B"), "AB")


class TestRoundTrips(unittest.TestCase):
    SAMPLES = ["", "<script>alert('xss')</script>", "héllo wörld ✓",
               "a b+c=d&e", "\x00\x01\x02", "emoji 🎯 test"]

    def test_every_codec_round_trips(self):
        # jwt is decode-only (see TestJwt); every reversible codec must
        # still round-trip exactly.
        for name, codec in CODECS.items():
            if name == "jwt":
                continue
            for s in self.SAMPLES:
                with self.subTest(codec=name, sample=repr(s)[:30]):
                    self.assertEqual(codec.decode(codec.encode(s)), s,
                                     f"{name} failed round-trip")


class TestJwt(unittest.TestCase):
    TOKEN = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    def test_decode_known_token(self):
        import json
        out = json.loads(CODECS["jwt"].decode(self.TOKEN))
        self.assertEqual(out["header"], {"alg": "HS256", "typ": "JWT"})
        self.assertEqual(out["payload"]["name"], "John Doe")
        self.assertEqual(out["payload"]["iat"], 1516239022)

    def test_signature_never_verified(self):
        # A token with a garbage signature still decodes: the signature
        # segment is ignored, never checked against any key.
        import json
        garbage = self.TOKEN.rsplit(".", 1)[0] + ".notarealsignature"
        out = json.loads(CODECS["jwt"].decode(garbage))
        self.assertEqual(out["payload"]["sub"], "1234567890")

    def test_two_segment_form(self):
        import json
        header_payload = self.TOKEN.rsplit(".", 1)[0]
        out = json.loads(CODECS["jwt"].decode(header_payload))
        self.assertEqual(out["header"]["alg"], "HS256")

    def test_encode_is_decode_only(self):
        with self.assertRaises(ValueError):
            CODECS["jwt"].encode("hello")

    def test_malformed_tokens_rejected(self):
        for bad in ("notatoken", "a.b", "a.b.c.d",
                    "!!!.eyJhIjogMX0.sig", "eyJhIjogMX0.!!!.sig",
                    "eyJhIjogMX0.WzFd.sig"):
            with self.subTest(token=bad):
                with self.assertRaises(ValueError):
                    CODECS["jwt"].decode(bad)

    def test_cli_decode_jwt(self):
        import subprocess
        import sys
        out = subprocess.run(
            [sys.executable, "-m", "payloadbox", "decode", "-c", "jwt",
             self.TOKEN], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('"John Doe"', out.stdout)
        bad = subprocess.run(
            [sys.executable, "-m", "payloadbox", "encode", "-c", "jwt",
             "hello"], capture_output=True, text=True, timeout=30)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("decode-only", bad.stderr)

    def test_chain_round_trip(self):
        original = "<img src=x onerror=alert(1)>"
        for chain in ("url,base64", "html,uni,hex", "url2,hexesc,oct,base64url",
                      "base64", "uni"):
            encoded = apply_chain(original, chain, "encode")
            self.assertEqual(apply_chain(encoded, chain, "decode"), original,
                             f"chain {chain} failed round-trip")

    def test_decode_reverses_encode_order(self):
        # encode: url then base64 ; decode must undo base64 then url
        step1 = apply_chain("<", "url", "encode")
        step2 = apply_chain(step1, "base64", "encode")
        self.assertEqual(apply_chain(step2, "url,base64", "decode"), "<")

    def test_rotN_chain(self):
        self.assertEqual(apply_chain("abcXYZ", "rot1", "encode"), "bcdYZA")
        self.assertEqual(apply_chain("bcdYZA", "rot1", "decode"), "abcXYZ")
        self.assertEqual(apply_chain("abc", "rot25", "encode"), "zab")
        # rotN composes with other codecs and inverts as a chain
        original = "<script>alert(1)</script>"
        encoded = apply_chain(original, "url,rot13", "encode")
        self.assertEqual(apply_chain(encoded, "url,rot13", "decode"), original)

    def test_xorN_chain(self):
        self.assertEqual(apply_chain("hello", "xor1", "encode"), "idmmn")
        self.assertEqual(apply_chain("idmmn", "xor1", "decode"), "hello")
        # xor0 is the identity; xor is its own inverse
        self.assertEqual(apply_chain("hello", "xor0", "encode"), "hello")
        self.assertEqual(apply_chain("A", "xor65", "encode"), "\x00")
        self.assertEqual(apply_chain("\x00", "xor65", "decode"), "A")
        # unicode round-trips through the latin-1-mapped xored bytes
        for key in (1, 65, 255):
            original = "héllo 🎯 <script>"
            encoded = apply_chain(original, f"xor{key}", "encode")
            self.assertEqual(apply_chain(encoded, f"xor{key}", "decode"),
                             original)
        # xorN composes with other codecs and inverts as a chain
        original = "<script>alert(1)</script>"
        encoded = apply_chain(original, "xor42,base64", "encode")
        self.assertEqual(apply_chain(encoded, "xor42,base64", "decode"),
                         original)

    def test_xorN_out_of_range(self):
        with self.assertRaises(ValueError):
            apply_chain("x", "xor256", "encode")

    def test_rotN_out_of_range(self):
        with self.assertRaises(ValueError):
            apply_chain("x", "rot26", "encode")

    def test_unknown_codec(self):
        with self.assertRaises(KeyError):
            apply_chain("x", "bogus", "encode")

    def test_bad_mode(self):
        with self.assertRaises(ValueError):
            apply_chain("x", "url", "sideways")

    def test_hex_decode_rejects_odd_length(self):
        with self.assertRaises(ValueError):
            CODECS["hex"].decode("abc")


class TestDetect(unittest.TestCase):
    def test_detect_url(self):
        self.assertIn("url", [n for n, _ in detect("%3Cscript%3E")])

    def test_detect_url2(self):
        self.assertIn("url2", [n for n, _ in detect("%253C")])

    def test_detect_html(self):
        self.assertIn("html", [n for n, _ in detect("&lt;script&gt;")])

    def test_detect_uni(self):
        self.assertIn("uni", [n for n, _ in detect("\\u003cscript\\u003e")])

    def test_detect_hex(self):
        self.assertIn("hex", [n for n, _ in detect("3c7363726970743e")])

    def test_detect_hexesc(self):
        self.assertIn("hexesc", [n for n, _ in detect("\\x3cscript\\x3e")])

    def test_detect_base64(self):
        names = [n for n, _ in detect("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")]
        self.assertTrue(any("base64" in n for n in names))

    def test_detect_base32(self):
        names = [n for n, _ in detect("NBSWY3DP")]
        self.assertIn("base32", names)
        # base32 is listed before base64, so --auto peels it as base32
        b64 = next(n for n in names if "base64" in n)
        self.assertLess(names.index("base32"), names.index(b64))
        # lowercase base64 stays base64, not base32
        self.assertNotIn("base32", [n for n, _ in detect("aGVsbG8=")])
        # pure-hex blobs stay hex, not base32
        self.assertNotIn("base32", [n for n, _ in detect("41424344")])
        # two "=" of padding is never valid base32, so not claimed
        self.assertNotIn("base32", [n for n, _ in detect("NBSWY3==")])

    def test_detect_zlib(self):
        blob = CODECS["zlib"].encode("hello world, this is a payload")
        names = [n for n, _ in detect(blob)]
        self.assertIn("zlib", names)
        # plain text starting with 'x' and truncated streams are not claimed
        self.assertNotIn("zlib", [n for n, _ in detect("xylophone")])
        self.assertNotIn("zlib", [n for n, _ in detect(blob[:-2])])
        self.assertNotIn("zlib", [n for n, _ in detect("x\x9c\xff\xff")])

    def test_detect_plain_text_no_hits(self):
        self.assertEqual(detect("hello world"), [])

    def test_detect_qp(self):
        self.assertIn("qp", [n for n, _ in detect("hello=20world")])
        self.assertIn("qp", [n for n, _ in detect("caf=C3=A9")])

    def test_detect_utf16(self):
        self.assertIn("utf16le", [n for n, _ in detect("h\x00e\x00l\x00l\x00o\x00")])
        self.assertIn("utf16be", [n for n, _ in detect("\x00h\x00e\x00l\x00l\x00o")])
        # bare NUL runs and odd lengths are not claimed
        self.assertNotIn("utf16le", [n for n, _ in detect("\x00\x00\x00\x00")])
        self.assertNotIn("utf16le", [n for n, _ in detect("a\x00b")])


class TestAutoDecode(unittest.TestCase):
    def test_double_url(self):
        # url2_decode already peels both percent layers in one step.
        text, steps = auto_decode("%253Cscript%253E")
        self.assertEqual(text, "<script>")
        self.assertEqual(steps, ["url2"])

    def test_base64_of_url(self):
        blob = CODECS["base64"].encode(CODECS["url"].encode("<script>"))
        text, steps = auto_decode(blob)
        self.assertEqual(text, "<script>")
        self.assertEqual(steps, ["base64", "url"])

    def test_auto_base32(self):
        text, steps = auto_decode("NBSWY3DP")
        self.assertEqual(text, "hello")
        self.assertEqual(steps, ["base32"])

    def test_auto_zlib(self):
        blob = CODECS["zlib"].encode("<script>alert(1)</script>")
        text, steps = auto_decode(blob)
        self.assertEqual(text, "<script>alert(1)</script>")
        self.assertEqual(steps, ["zlib"])

    def test_auto_zlib_inside_base64(self):
        # compress-then-encode chain: base64 peels first, then zlib
        blob = CODECS["base64"].encode(CODECS["zlib"].encode("<script>"))
        text, steps = auto_decode(blob)
        self.assertEqual(text, "<script>")
        self.assertEqual(steps, ["base64", "zlib"])

    def test_plain_text_unchanged(self):
        self.assertEqual(auto_decode("hello world"), ("hello world", []))

    def test_max_steps_guard(self):
        # Two layers (base64 over url) but only one step allowed.
        blob = CODECS["base64"].encode(CODECS["url"].encode("<"))
        text, steps = auto_decode(blob, max_steps=1)
        self.assertEqual((text, steps), ("%3C", ["base64"]))

    def test_undecodable_blob_stops(self):
        # Looks hex-ish but decodes to invalid UTF-8; returned unchanged.
        self.assertEqual(auto_decode("ffff"), ("ffff", []))

    def test_detect_empty_no_hits(self):
        self.assertEqual(detect(""), [])

    def test_auto_utf16_of_url(self):
        blob = CODECS["utf16le"].encode(CODECS["url"].encode("<script>"))
        text, steps = auto_decode(blob)
        self.assertEqual(text, "<script>")
        self.assertEqual(steps, ["utf16le", "url"])


if __name__ == "__main__":
    unittest.main()
