"""
pe_cli.py — Minimal PE / CLI metadata reader.

Parses just enough of a .NET PE file (DOS header -> PE header -> Optional
header -> Data Directories -> CLR Runtime Header -> CLI metadata root ->
#~ stream tables) to locate MethodDef rows and read their IL method bodies.

Reference: ECMA-335, 6th edition, Partition II (Metadata) and
Partition III (CIL Instruction Set).

This is a teaching / research tool, not a full-spec parser: it covers the
five tables needed to walk from a TypeDef down to a method body
(Module, TypeRef, TypeDef, Field, MethodDef, Param) which is enough for
the vast majority of real-world assemblies. Tables it doesn't understand
are skipped by size, not content, so row *offsets* stay correct even
though their *contents* aren't decoded.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field


class PEFormatError(Exception):
    pass


# ---------------------------------------------------------------------------
# Low level byte reader
# ---------------------------------------------------------------------------

class Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def u8(self) -> int:
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        v = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return v

    def u32(self) -> int:
        v = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return v

    def bytes(self, n: int) -> bytes:
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v

    def cstr(self) -> str:
        start = self.pos
        end = self.data.index(b"\x00", start)
        s = self.data[start:end].decode("utf-8", errors="replace")
        self.pos = end + 1
        return s


# ---------------------------------------------------------------------------
# PE / COFF / Optional header
# ---------------------------------------------------------------------------

@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_ptr: int


@dataclass
class PEImage:
    data: bytes
    sections: list = field(default_factory=list)
    is_pe32_plus: bool = False
    clr_header_rva: int = 0
    clr_header_size: int = 0

    def rva_to_offset(self, rva: int) -> int:
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                return s.raw_ptr + (rva - s.virtual_address)
        raise PEFormatError(f"RVA 0x{rva:x} not found in any section")


def parse_pe(data: bytes) -> PEImage:
    r = Reader(data)
    if data[0:2] != b"MZ":
        raise PEFormatError("not an MZ/DOS executable")
    r.pos = 0x3C
    pe_offset = r.u32()

    r.pos = pe_offset
    if r.bytes(4) != b"PE\x00\x00":
        raise PEFormatError("missing PE signature")

    machine = r.u16()  # noqa: F841
    num_sections = r.u16()
    r.u32()  # timestamp
    r.u32()  # symbol table ptr
    r.u32()  # num symbols
    opt_header_size = r.u16()
    r.u16()  # characteristics

    opt_header_start = r.pos
    magic = r.u16()
    is_plus = magic == 0x20B  # PE32+ (64-bit)

    # Skip to NumberOfRvaAndSizes then Data Directories.
    # Layout differs slightly between PE32 and PE32+, so jump by known
    # fixed offsets from the start of the optional header.
    if is_plus:
        data_dir_offset = opt_header_start + 112
    else:
        data_dir_offset = opt_header_start + 96

    r.pos = data_dir_offset
    # Data directory 14 (index 14, zero-based) is the CLR Runtime Header.
    CLR_HEADER_INDEX = 14
    r.pos = data_dir_offset + CLR_HEADER_INDEX * 8
    clr_rva = r.u32()
    clr_size = r.u32()

    # Section headers follow the optional header.
    r.pos = opt_header_start + opt_header_size
    sections = []
    for _ in range(num_sections):
        raw_name = r.bytes(8)
        name = raw_name.rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = r.u32()
        vaddr = r.u32()
        rawsize = r.u32()
        rawptr = r.u32()
        r.bytes(16)  # reloc ptr, line num ptr, reloc count, line count, characteristics(4)
        sections.append(Section(name, vsize, vaddr, rawsize, rawptr))

    img = PEImage(data=data, sections=sections, is_pe32_plus=is_plus,
                  clr_header_rva=clr_rva, clr_header_size=clr_size)
    if clr_rva == 0:
        raise PEFormatError("no CLR Runtime Header — this is not a .NET assembly")
    return img


# ---------------------------------------------------------------------------
# CLR / COR20 header + CLI metadata root
# ---------------------------------------------------------------------------

@dataclass
class Cor20Header:
    metadata_rva: int
    metadata_size: int
    entrypoint_token: int


def parse_cor20(img: PEImage) -> Cor20Header:
    off = img.rva_to_offset(img.clr_header_rva)
    r = Reader(img.data, off)
    cb = r.u32()  # noqa: F841  size of this header
    r.u16(); r.u16()  # major/minor runtime version
    md_rva = r.u32()
    md_size = r.u32()
    r.u32()  # flags
    entrypoint = r.u32()
    return Cor20Header(md_rva, md_size, entrypoint)


@dataclass
class StreamHeader:
    name: str
    offset: int  # relative to metadata root
    size: int


def parse_metadata_root(img: PEImage, cor20: Cor20Header):
    root_off = img.rva_to_offset(cor20.metadata_rva)
    r = Reader(img.data, root_off)
    sig = r.u32()
    if sig != 0x424A5342:  # "BSJB"
        raise PEFormatError("bad metadata root signature")
    r.u16(); r.u16()  # major/minor version
    r.u32()  # reserved
    version_len = r.u32()
    version = r.bytes(version_len).rstrip(b"\x00").decode("utf-8", errors="replace")
    # padding to 4-byte alignment already accounted for since version_len is
    # itself 4-byte aligned per spec
    r.u16()  # flags
    num_streams = r.u16()

    streams = []
    for _ in range(num_streams):
        s_off = r.u32()
        s_size = r.u32()
        name = r.cstr()
        # stream headers are 4-byte aligned
        pad = (-r.pos) % 4
        r.pos += pad
        streams.append(StreamHeader(name, s_off, s_size))
    return root_off, version, streams


# ---------------------------------------------------------------------------
# #~ tables stream — just enough to reach MethodDef rows
# ---------------------------------------------------------------------------

TABLE_MODULE = 0x00
TABLE_TYPEREF = 0x01
TABLE_TYPEDEF = 0x02
TABLE_FIELD = 0x04
TABLE_METHODDEF = 0x06
TABLE_PARAM = 0x08

TABLE_NAMES = {
    TABLE_MODULE: "Module", TABLE_TYPEREF: "TypeRef", TABLE_TYPEDEF: "TypeDef",
    TABLE_FIELD: "Field", TABLE_METHODDEF: "MethodDef", TABLE_PARAM: "Param",
}


@dataclass
class TablesStream:
    heap_sizes: int
    row_counts: dict  # table_id -> row count (only for tables present)
    table_data_offset: int  # offset (into full file) where row data begins


def _coded_index_size(tag_bits: int, table_ids: list, row_counts: dict) -> int:
    max_rows = max((row_counts.get(t, 0) for t in table_ids), default=0)
    return 4 if max_rows > (1 << (16 - tag_bits)) else 2


def parse_tables_stream(img: PEImage, meta_root_off: int, streams: list):
    tilde = next((s for s in streams if s.name == "#~"), None)
    if tilde is None:
        raise PEFormatError("no #~ (compressed tables) stream — uncompressed #- not supported")

    base = meta_root_off + tilde.offset
    r = Reader(img.data, base)
    r.u32()  # reserved
    r.u8(); r.u8()  # major/minor table schema version
    heap_sizes = r.u8()
    r.u8()  # reserved (always 1)
    valid = r.bytes(8)
    valid_mask = int.from_bytes(valid, "little")
    r.bytes(8)  # sorted mask

    row_counts = {}
    for i in range(64):
        if valid_mask & (1 << i):
            row_counts[i] = r.u32()

    return TablesStream(heap_sizes=heap_sizes, row_counts=row_counts,
                         table_data_offset=r.pos), valid_mask


@dataclass
class MethodDefRow:
    rva: int
    impl_flags: int
    flags: int
    name_idx: int
    signature_idx: int
    param_list: int


def read_methoddef_rows(img: PEImage, ts: TablesStream) -> list:
    """Walk Module, TypeRef, TypeDef, Field rows by size (contents ignored)
    to reach the MethodDef table, then decode every MethodDef row."""

    str_idx_size = 4 if (ts.heap_sizes & 0x01) else 2
    guid_idx_size = 4 if (ts.heap_sizes & 0x02) else 2
    blob_idx_size = 4 if (ts.heap_sizes & 0x04) else 2

    rc = ts.row_counts

    # coded index widths we need
    resolution_scope_size = _coded_index_size(
        2, [TABLE_MODULE, 0x1A, 0x23, TABLE_TYPEREF], rc)  # ModuleRef=0x1A, AssemblyRef=0x23
    type_def_or_ref_size = _coded_index_size(
        2, [TABLE_TYPEDEF, TABLE_TYPEREF, 0x1B], rc)  # TypeSpec=0x1B

    field_table_rows = rc.get(TABLE_FIELD, 0)
    method_table_rows = rc.get(TABLE_METHODDEF, 0)
    param_table_rows = rc.get(TABLE_PARAM, 0)

    field_idx_size = 4 if field_table_rows > 0xFFFF else 2
    method_idx_size = 4 if method_table_rows > 0xFFFF else 2
    param_idx_size = 4 if param_table_rows > 0xFFFF else 2

    r = Reader(img.data, ts.table_data_offset)

    def skip(n_bytes):
        r.pos += n_bytes

    # Module: Generation(2) + Name(str) + Mvid(guid) + EncId(guid) + EncBaseId(guid)
    for _ in range(rc.get(TABLE_MODULE, 0)):
        skip(2 + str_idx_size + guid_idx_size * 3)

    # TypeRef: ResolutionScope(coded) + Name(str) + Namespace(str)
    for _ in range(rc.get(TABLE_TYPEREF, 0)):
        skip(resolution_scope_size + str_idx_size * 2)

    # TypeDef: Flags(4) + Name(str) + Namespace(str) + Extends(coded)
    #          + FieldList(field idx) + MethodList(method idx)
    for _ in range(rc.get(TABLE_TYPEDEF, 0)):
        skip(4 + str_idx_size * 2 + type_def_or_ref_size + field_idx_size + method_idx_size)

    # Field: Flags(2) + Name(str) + Signature(blob)
    for _ in range(rc.get(TABLE_FIELD, 0)):
        skip(2 + str_idx_size + blob_idx_size)

    # --- MethodDef rows: this is what we actually want ---
    rows = []
    for _ in range(method_table_rows):
        rva = r.u32()
        impl_flags = r.u16()
        flags = r.u16()
        name_idx = r.u16() if str_idx_size == 2 else r.u32()
        sig_idx = r.u16() if blob_idx_size == 2 else r.u32()
        plist = r.u16() if param_idx_size == 2 else r.u32()
        rows.append(MethodDefRow(rva, impl_flags, flags, name_idx, sig_idx, plist))

    return rows


def read_string_heap_name(img: PEImage, meta_root_off: int, streams: list, idx: int) -> str:
    strings = next((s for s in streams if s.name == "#Strings"), None)
    if strings is None or idx == 0:
        return ""
    off = meta_root_off + strings.offset + idx
    r = Reader(img.data, off)
    return r.cstr()
