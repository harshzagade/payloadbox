"""CLI smoke tests for PayloadBox (subprocess, no network)."""
import subprocess
import sys
import unittest

PKG = ["python3", "-m", "payloadbox"]


def run(*args, stdin=None):
    return subprocess.run(PKG + list(args), input=stdin, capture_output=True,
                          text=True, timeout=30)


class TestCli(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        enc = run("encode", "-c", "url,base64", "<script>alert(1)</script>")
        self.assertEqual(enc.returncode, 0, enc.stderr)
        dec = run("decode", "-c", "url,base64", enc.stdout.strip())
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(dec.stdout.strip(), "<script>alert(1)</script>")

    def test_stdin_pipe(self):
        enc = run("encode", "-c", "hex", stdin="AB")
        self.assertEqual(enc.returncode, 0, enc.stderr)
        self.assertEqual(enc.stdout.strip(), "4142")

    def test_list_shows_all_codecs(self):
        out = run("list")
        self.assertEqual(out.returncode, 0, out.stderr)
        for name in ("url", "url2", "html", "uni", "hex", "hexesc", "oct",
                     "base64", "base64url"):
            self.assertIn(name, out.stdout)

    def test_detect_cli(self):
        out = run("detect", "aGVsbG8=")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("base64", out.stdout)

    def test_detect_json(self):
        import json
        out = run("detect", "--json", "aGVsbG8=")
        self.assertEqual(out.returncode, 0, out.stderr)
        hits = json.loads(out.stdout)
        self.assertIsInstance(hits, list)
        self.assertTrue(any("base64" in h["encoding"] for h in hits))
        self.assertTrue(all("evidence" in h for h in hits))
        # plain text: machine-readable empty list, not the human message
        out = run("detect", "--json", "hello world")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout), [])

    def test_unknown_codec_errors(self):
        out = run("encode", "-c", "bogus", "x")
        self.assertEqual(out.returncode, 1)
        self.assertIn("unknown codec", out.stderr)

    def test_rot_option(self):
        enc = run("encode", "--rot", "13", "Hello")
        self.assertEqual(enc.returncode, 0, enc.stderr)
        self.assertEqual(enc.stdout.strip(), "Uryyb")
        dec = run("decode", "--rot", "13", "Uryyb")
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(dec.stdout.strip(), "Hello")
        # --rot composes after an explicit chain (base64 output, then shift)
        enc = run("encode", "-c", "base64", "--rot", "1", "hello")
        self.assertEqual(enc.returncode, 0, enc.stderr)
        self.assertEqual(enc.stdout.strip(), "bHWtcH8=")
        dec = run("decode", "-c", "base64", "--rot", "1", "bHWtcH8=")
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(dec.stdout.strip(), "hello")
        out = run("encode", "--rot", "26", "x")
        self.assertEqual(out.returncode, 2)

    def test_xor_option(self):
        enc = run("encode", "--xor", "1", "hello")
        self.assertEqual(enc.returncode, 0, enc.stderr)
        self.assertEqual(enc.stdout.strip(), "idmmn")
        dec = run("decode", "--xor", "1", "idmmn")
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(dec.stdout.strip(), "hello")
        # --xor composes after an explicit chain (base64 output, then xor)
        enc = run("encode", "-c", "base64", "--xor", "1", "hello")
        self.assertEqual(enc.returncode, 0, enc.stderr)
        self.assertEqual(enc.stdout.strip(), "`FWrcF9<")
        dec = run("decode", "-c", "base64", "--xor", "1", "`FWrcF9<")
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(dec.stdout.strip(), "hello")
        # --rot and --xor together: rot applies first, then xor
        enc = run("encode", "--rot", "1", "--xor", "1", "hello")
        self.assertEqual(enc.returncode, 0, enc.stderr)
        dec = run("decode", "--rot", "1", "--xor", "1", enc.stdout.strip())
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(dec.stdout.strip(), "hello")
        out = run("encode", "--xor", "256", "x")
        self.assertEqual(out.returncode, 2)
        out = run("decode", "--auto", "--xor", "1", "x")
        self.assertEqual(out.returncode, 2)

    def test_auto_decode_cli(self):
        out = run("decode", "--auto", "%253Cscript%253E")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "<script>")
        self.assertIn("url2", out.stderr)
        out = run("decode", "--auto", "hello world")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "hello world")
        out = run("decode", "--auto", "-c", "url", "%3C")
        self.assertEqual(out.returncode, 2)

    def test_preset_option(self):
        enc = run("encode", "--preset", "waf", "<script>")
        self.assertEqual(enc.returncode, 0, enc.stderr)
        ref = run("encode", "-c", "url,base64", "<script>")
        self.assertEqual(enc.stdout, ref.stdout)
        dec = run("decode", "--preset", "waf", enc.stdout.strip())
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(dec.stdout.strip(), "<script>")
        # double preset is double percent-encoding, like url2
        enc = run("encode", "--preset", "double", "<script>")
        ref = run("encode", "-c", "url2", "<script>")
        self.assertEqual(enc.stdout, ref.stdout)
        # --preset composes with --rot
        enc = run("encode", "--preset", "waf", "--rot", "1", "hello")
        self.assertEqual(enc.returncode, 0, enc.stderr)
        dec = run("decode", "--preset", "waf", "--rot", "1", enc.stdout.strip())
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(dec.stdout.strip(), "hello")
        # unknown preset errors
        out = run("encode", "--preset", "bogus", "x")
        self.assertEqual(out.returncode, 1)
        self.assertIn("unknown preset", out.stderr)
        # --preset conflicts with -c and with --auto
        out = run("encode", "--preset", "waf", "-c", "url", "x")
        self.assertEqual(out.returncode, 2)
        out = run("decode", "--auto", "--preset", "waf", "x")
        self.assertEqual(out.returncode, 2)

    def test_list_shows_presets(self):
        out = run("list")
        self.assertEqual(out.returncode, 0, out.stderr)
        for name in ("waf", "double", "b64double", "json", "deep"):
            self.assertIn(name, out.stdout)

    def test_utf7_codec_cli(self):
        enc = run("encode", "-c", "utf7", "<script>")
        self.assertEqual(enc.returncode, 0, enc.stderr)
        self.assertEqual(enc.stdout.strip(), "+ADw-script+AD4-")
        dec = run("decode", "-c", "utf7", "+ADw-script+AD4-")
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(dec.stdout.strip(), "<script>")
        out = run("decode", "--auto", "+ADw-script+AD4-")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "<script>")
        self.assertIn("utf7", out.stderr)

    def test_version(self):
        out = run("--version")
        self.assertEqual(out.returncode, 0)
        self.assertIn("payloadbox", out.stdout)


if __name__ == "__main__":
    unittest.main()
