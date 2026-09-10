# il-disassembler

A from-scratch CIL (Common Intermediate Language) disassembler for .NET
PE binaries, written in pure Python with no dependencies — no
`dnlib`, no `Mono.Cecil`, no `pythonnet`.

Built while working through a HackTheBox reverse-engineering challenge
that involved a stripped `.apk`/PE binary with no readable strings and
no existing tool that could parse it out of the box. This is the
disassembler side of that: read the PE headers, walk the CLI metadata
tables by hand, pull out method bodies, and decode their IL bytes into
readable instructions.

## What it does

1. Parses the DOS/PE/COFF headers and locates the CLR Runtime Header
   (data directory 14) — `pe_cli.py`
2. Reads the COR20 header to find the CLI metadata root (`BSJB` signature)
3. Parses the `#~` compressed metadata tables stream: works out heap
   index widths and coded-index widths per ECMA-335, then walks
   `Module → TypeRef → TypeDef → Field → MethodDef` row by row to reach
   every method's RVA
4. Reads each method body (tiny or fat header format) to get the raw
   CIL byte stream — `disassembler.py`
5. Decodes every opcode (including the `0xFE`-prefixed extended set)
   into a mnemonic + operand — `il_opcodes.py`

No table content beyond what's needed is decoded — tables it doesn't
care about are skipped *by size*, not ignored, so row offsets for the
tables it does read stay correct.

## Usage

```bash
python src/main.py path/to/binary.exe
python src/main.py path/to/binary.dll --method Add   # filter by method name
```

## Example

```
=== Add  (RVA=0x2058, flags=0x0096) ===
  header: fat, max_stack=2, code_size=6
  IL_0000:   ldarg.0
  IL_0001:   ldarg.1
  IL_0002:   add
  IL_0003:   stloc.0
  IL_0004:   ldloc.0
  IL_0005:   ret
```

## Tests

`tests/` has two small C# programs (`Sample.cs`, `Sample2.cs` — one
plain, one with a loop/branch/string) used to validate the disassembler
against real compiled output. Compile them with `mcs` (Mono C#
compiler) or `csc`/`dotnet build` and run the tool against the result:

```bash
mcs -target:exe -out:tests/Sample.exe tests/Sample.cs
python src/main.py tests/Sample.exe
```

## Known limitations

- Only the five metadata tables needed to reach `MethodDef` are decoded
  (`Module`, `TypeRef`, `TypeDef`, `Field`, `MethodDef`, `Param`). Others
  are skipped by size, so names/signatures beyond method names aren't
  resolved yet.
- No generics (`MethodSpec`/`TypeSpec` signature decoding) yet.
- No exception-handler table parsing (fat header's extra data section).
- Signature blobs (parameter/return types) aren't decoded — you get the
  metadata token, not the resolved type name.

Pull requests welcome if you want to extend the table coverage.

## Reference

[ECMA-335, 6th edition](https://ecma-international.org/publications-and-standards/standards/ecma-335/) —
Partition II (Metadata) and Partition III (CIL Instruction Set).

## License

MIT
