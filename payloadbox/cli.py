"""Command-line interface for PayloadBox."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .codecs import CODECS, apply_chain, detect


def _read_input(args: argparse.Namespace) -> str:
    if args.text is not None:
        return args.text
    if args.input_file:
        with open(args.input_file, encoding="utf-8") as f:
            return f.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    print("error: no input — pass TEXT, --input-file, or pipe via stdin",
          file=sys.stderr)
    raise SystemExit(2)


def _write_output(args: argparse.Namespace, text: str) -> None:
    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        # Avoid trailing-newline surprises when piping; keep one newline.
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def cmd_convert(args: argparse.Namespace, mode: str) -> int:
    try:
        text = _read_input(args)
        result = apply_chain(text, args.chain, mode)
    except (KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        print(f"error: undecodable input for this chain: {e}", file=sys.stderr)
        return 1
    _write_output(args, result)
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    width = max(len(c.name) for c in CODECS.values())
    for codec in CODECS.values():
        print(f"{codec.name:<{width}}  {codec.description}")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    text = _read_input(args)
    hits = detect(text)
    if not hits:
        print("no known encoding detected")
        return 0
    width = max(len(name) for name, _ in hits)
    for name, reason in hits:
        print(f"{name:<{width}}  {reason}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="payloadbox",
        description="Encoder/decoder chains for payloads: URL, double-URL, "
                    "HTML entity, unicode, hex, base64 and more.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_io(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("text", nargs="?", help="input text (else stdin)")
        sp.add_argument("-i", "--input-file", help="read input from file")
        sp.add_argument("-o", "--output-file", help="write output to file")

    enc = sub.add_parser("encode", help="encode input through a codec chain")
    enc.add_argument("-c", "--chain", default="url",
                     help="comma-separated codecs, applied left to right "
                          "(default: url)")
    add_io(enc)
    enc.set_defaults(func=lambda a: cmd_convert(a, "encode"))

    dec = sub.add_parser("decode", help="decode input (chain applied in reverse)")
    dec.add_argument("-c", "--chain", default="url",
                     help="same chain string used for encoding; it is "
                          "undone in reverse order")
    add_io(dec)
    dec.set_defaults(func=lambda a: cmd_convert(a, "decode"))

    lst = sub.add_parser("list", help="list available codecs")
    lst.set_defaults(func=cmd_list)

    det = sub.add_parser("detect", help="guess which encodings are present")
    add_io(det)
    det.set_defaults(func=cmd_detect)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
