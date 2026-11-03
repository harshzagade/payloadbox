"""Command-line interface for PayloadBox."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .codecs import CODECS, apply_chain, auto_decode, detect


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


def _rot_shift(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"rot shift must be 0-25, got {value!r}")
    if not 0 <= n <= 25:
        raise argparse.ArgumentTypeError(f"rot shift must be 0-25, got {n}")
    return n


def cmd_convert(args: argparse.Namespace, mode: str) -> int:
    if mode == "decode" and getattr(args, "auto", False):
        if args.chain is not None or getattr(args, "rot", None) is not None:
            print("error: --auto cannot be combined with -c/--chain or --rot",
                  file=sys.stderr)
            return 2
        try:
            text = _read_input(args)
            result, steps = auto_decode(text)
        except (ValueError, UnicodeDecodeError, UnicodeEncodeError) as e:
            print(f"error: undecodable input: {e}", file=sys.stderr)
            return 1
        if steps:
            print(f"decoded via: {' -> '.join(steps)}", file=sys.stderr)
        _write_output(args, result)
        return 0
    chain = args.chain if args.chain is not None else "url"
    if getattr(args, "rot", None) is not None:
        chain = f"{chain},rot{args.rot}" if args.chain is not None \
            else f"rot{args.rot}"
    try:
        text = _read_input(args)
        result = apply_chain(text, chain, mode)
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
    enc.add_argument("-c", "--chain", default=None,
                     help="comma-separated codecs, applied left to right "
                          "(default: url)")
    enc.add_argument("--rot", type=_rot_shift, default=None, metavar="N",
                     help="Caesar-shift the result by N (0-25); applied "
                          "after the chain, or alone when -c is omitted")
    add_io(enc)
    enc.set_defaults(func=lambda a: cmd_convert(a, "encode"))

    dec = sub.add_parser("decode", help="decode input (chain applied in reverse)")
    dec.add_argument("-c", "--chain", default=None,
                     help="same chain string used for encoding; it is "
                          "undone in reverse order")
    dec.add_argument("--rot", type=_rot_shift, default=None, metavar="N",
                     help="undo a Caesar shift of N (0-25); applied before "
                          "the chain is undone, or alone when -c is omitted")
    dec.add_argument("--auto", action="store_true",
                     help="detect encodings and decode repeatedly until "
                          "plain text (loop-guarded); cannot combine with "
                          "-c/--chain or --rot")
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
