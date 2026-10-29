"""Tests for payloadbox.codecs — known vectors + round-trips."""
import unittest

from payloadbox.codecs import CODECS, apply_chain, detect


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


class TestRoundTrips(unittest.TestCase):
    SAMPLES = ["", "<script>alert('xss')</script>", "héllo wörld ✓",
               "a b+c=d&e", "\x00\x01\x02", "emoji 🎯 test"]

    def test_every_codec_round_trips(self):
        for name, codec in CODECS.items():
            for s in self.SAMPLES:
                with self.subTest(codec=name, sample=repr(s)[:30]):
                    self.assertEqual(codec.decode(codec.encode(s)), s,
                                     f"{name} failed round-trip")

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

    def test_unknown_codec(self):
        with self.assertRaises(KeyError):
            apply_chain("x", "rot13", "encode")

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

    def test_detect_plain_text_no_hits(self):
        self.assertEqual(detect("hello world"), [])

    def test_detect_empty_no_hits(self):
        self.assertEqual(detect(""), [])


if __name__ == "__main__":
    unittest.main()
