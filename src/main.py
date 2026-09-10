#!/usr/bin/env python3
"""
il-disassembler — a from-scratch CIL disassembler for .NET PE binaries.

Usage:
    python main.py <path-to-dll-or-exe> [--method NAME_SUBSTRING]

Walks: DOS/PE headers -> CLR Runtime Header -> CLI metadata root ->
#~ tables stream -> MethodDef table -> method body -> CIL bytes ->
readable IL instructions. No external dependencies, no dnlib/Mono.Cecil —
every one of those steps is hand-parsed per ECMA-335.
"""
import argparse
import sys

from pe_cli import (parse_pe, parse_cor20, parse_metadata_root,
                     parse_tables_stream, read_methoddef_rows,
                     read_string_heap_name, PEFormatError)
from disassembler import read_method_body, disassemble, format_instructions


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", help="path to a .NET .dll or .exe")
    ap.add_argument("--method", default=None,
                     help="only disassemble methods whose name contains this substring")
    args = ap.parse_args()

    with open(args.binary, "rb") as f:
        data = f.read()

    try:
        img = parse_pe(data)
        cor20 = parse_cor20(img)
        root_off, version, streams = parse_metadata_root(img, cor20)
        print(f"CLR metadata version: {version}")
        print(f"Streams: {', '.join(s.name for s in streams)}\n")

        ts, valid_mask = parse_tables_stream(img, root_off, streams)
        methods = read_methoddef_rows(img, ts)
        print(f"Found {len(methods)} method(s) in MethodDef table.\n")

        shown = 0
        for m in methods:
            name = read_string_heap_name(img, root_off, streams, m.name_idx)
            if args.method and args.method.lower() not in name.lower():
                continue
            print(f"=== {name}  (RVA=0x{m.rva:x}, flags=0x{m.flags:04x}) ===")
            if m.rva == 0:
                print("  (no body — abstract/extern/P-Invoke)\n")
                continue
            body = read_method_body(img, m.rva)
            print(f"  header: {body.header_kind}, max_stack={body.max_stack}, "
                  f"code_size={body.code_size}")
            instrs = disassemble(body.il_bytes)
            print(format_instructions(instrs))
            print()
            shown += 1

        if shown == 0:
            print("No methods matched." if args.method else "No method bodies with code.")

    except PEFormatError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
