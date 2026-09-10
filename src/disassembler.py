"""
disassembler.py — reads a method body (tiny or fat format, ECMA-335
II.25.4) and disassembles its CIL bytes into readable instruction text.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from il_opcodes import lookup, OPERAND_SIZE, BR1, BR4, SWITCH, STR, TOK, VAR, VAR1, I1


@dataclass
class MethodBody:
    header_kind: str      # "tiny" or "fat"
    max_stack: int
    code_size: int
    local_var_sig_tok: int
    il_bytes: bytes


def read_method_body(img, rva: int) -> MethodBody:
    off = img.rva_to_offset(rva)
    first = img.data[off]

    if (first & 0x03) == 0x02:  # tiny format
        code_size = first >> 2
        il = img.data[off + 1: off + 1 + code_size]
        return MethodBody("tiny", max_stack=8, code_size=code_size,
                           local_var_sig_tok=0, il_bytes=il)

    # fat format
    flags_and_size = struct.unpack_from("<H", img.data, off)[0]
    header_size_dwords = (flags_and_size >> 12) & 0x0F
    max_stack = struct.unpack_from("<H", img.data, off + 2)[0]
    code_size = struct.unpack_from("<I", img.data, off + 4)[0]
    local_sig_tok = struct.unpack_from("<I", img.data, off + 8)[0]
    body_start = off + header_size_dwords * 4
    il = img.data[body_start: body_start + code_size]
    return MethodBody("fat", max_stack=max_stack, code_size=code_size,
                       local_var_sig_tok=local_sig_tok, il_bytes=il)


@dataclass
class Instruction:
    offset: int
    mnemonic: str
    operand_text: str
    raw: bytes


def disassemble(il_bytes: bytes) -> list:
    instrs = []
    pos = 0
    n = len(il_bytes)
    while pos < n:
        start = pos
        b0 = il_bytes[pos]
        if b0 == 0xFE:
            b1 = il_bytes[pos + 1]
            name, kind, opcode_len = lookup(b0, b1)
        else:
            name, kind, opcode_len = lookup(b0)
        pos += opcode_len

        operand_text = ""
        if kind == SWITCH:
            count = struct.unpack_from("<I", il_bytes, pos)[0]
            pos += 4
            targets = []
            for _ in range(count):
                targets.append(struct.unpack_from("<i", il_bytes, pos)[0])
                pos += 4
            operand_text = "(" + ", ".join(f"{t:+d}" for t in targets) + ")"
        elif kind != "none":
            size = OPERAND_SIZE[kind]
            raw_operand = il_bytes[pos:pos + size]
            pos += size
            if kind == BR1:
                val = struct.unpack("<b", raw_operand)[0]
                operand_text = f"{val:+d} -> IL_{pos + val:04x}"
            elif kind == BR4:
                val = struct.unpack("<i", raw_operand)[0]
                operand_text = f"{val:+d} -> IL_{pos + val:04x}"
            elif kind in (STR, TOK):
                tok = struct.unpack("<I", raw_operand)[0]
                operand_text = f"0x{tok:08X}"
            elif kind == VAR:
                operand_text = str(struct.unpack("<H", raw_operand)[0])
            elif kind == VAR1 or kind == I1:
                operand_text = str(struct.unpack("<b", raw_operand)[0])
            elif kind == "int32":
                operand_text = str(struct.unpack("<i", raw_operand)[0])
            elif kind == "int64":
                operand_text = str(struct.unpack("<q", raw_operand)[0])
            elif kind == "float32":
                operand_text = str(struct.unpack("<f", raw_operand)[0])
            elif kind == "float64":
                operand_text = str(struct.unpack("<d", raw_operand)[0])
            else:
                operand_text = raw_operand.hex()

        instrs.append(Instruction(start, name, operand_text, il_bytes[start:pos]))
    return instrs


def format_instructions(instrs: list) -> str:
    lines = []
    for ins in instrs:
        addr = f"IL_{ins.offset:04x}:"
        if ins.operand_text:
            lines.append(f"  {addr:<10} {ins.mnemonic:<14} {ins.operand_text}")
        else:
            lines.append(f"  {addr:<10} {ins.mnemonic}")
    return "\n".join(lines)
