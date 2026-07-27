#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import string
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


class Die(Exception):
    pass


def run(cmd, *, check=True):
    try:
        p = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except FileNotFoundError as e:
        raise Die(f"missing command: {cmd[0]}") from e
    if check and p.returncode != 0:
        msg = p.stderr.strip() or p.stdout.strip() or f"exit {p.returncode}"
        raise Die(f"{' '.join(cmd)} failed: {msg}")
    return p


def extract_lib(apk_path, abi, out_dir):
    member = f"lib/{abi}/libclash.so"
    with zipfile.ZipFile(apk_path) as z:
        names = set(z.namelist())
        if member not in names:
            candidates = sorted(n for n in names if n.endswith("/libclash.so"))
            raise Die(
                f"{member} not found in APK. Available libclash.so entries: "
                + (", ".join(candidates) if candidates else "<none>")
            )
        out = Path(out_dir) / f"libclash_{abi}.so"
        with z.open(member) as src, out.open("wb") as dst:
            shutil.copyfileobj(src, dst)
    return out


def check_mihomo_symbols(lib_path):
    data = Path(lib_path).read_bytes()
    rx = rb"metacubex/mihomo/common/convert\.[A-Za-z0-9]+"
    symbols = sorted(set(m.group(0).decode("ascii") for m in re.finditer(rx, data)))
    has_decode = any(s.endswith("DecodeAESBase64") for s in symbols)
    has_aes = any(s.endswith("aesDecryptCBC") for s in symbols)
    if not (has_decode and has_aes):
        found = "\n".join(f"  {s}" for s in symbols[:50]) or "  <none>"
        raise Die(
            "mihomo convert DecodeAESBase64/aesDecryptCBC symbols were not found.\n"
            f"scanned convert symbols:\n{found}"
        )
    return symbols


def cstr(data, off):
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("utf-8", errors="replace")


def read_elf64_le_sections(data):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise Die("not an ELF64 little-endian file")

    shoff = int.from_bytes(data[40:48], "little")
    shentsize = int.from_bytes(data[58:60], "little")
    shnum = int.from_bytes(data[60:62], "little")
    shstrndx = int.from_bytes(data[62:64], "little")
    if shoff == 0 or shentsize == 0 or shnum == 0 or shstrndx >= shnum:
        raise Die("invalid section table")

    def raw_section(index):
        start = shoff + index * shentsize
        end = start + shentsize
        if start < 0 or end > len(data):
            raise Die("invalid section header")
        return data[start:end]

    shstr = raw_section(shstrndx)
    shstr_off = int.from_bytes(shstr[24:32], "little")
    shstr_size = int.from_bytes(shstr[32:40], "little")
    if shstr_off + shstr_size > len(data):
        raise Die("invalid shstrtab data")
    names = data[shstr_off : shstr_off + shstr_size]

    sections = []
    for i in range(shnum):
        s = raw_section(i)
        off = int.from_bytes(s[24:32], "little")
        size = int.from_bytes(s[32:40], "little")
        sections.append(
            {
                "name": cstr(names, int.from_bytes(s[0:4], "little")),
                "addr": int.from_bytes(s[16:24], "little"),
                "off": off,
                "size": size,
                "data": data[off : off + size] if off + size <= len(data) else b"",
            }
        )
    return sections


class GoPclnTable:
    MAGICS = {
        0xFFFFFFFB: "ver12",
        0xFFFFFFFA: "ver116",
        0xFFFFFFF0: "ver118",
        0xFFFFFFF1: "ver120",
    }

    def __init__(self, pcln, text_addr):
        self.data = pcln
        self.text_addr = text_addr
        self.order = "little"
        self.version = None
        self.ptrsize = 0
        self.nfunctab = 0
        self.funcnametab = b""
        self.funcdata = b""
        self.functab = b""
        self.field_size = 0
        self._parse_header()

    def _uint(self, data, off, size):
        if off < 0 or off + size > len(data):
            raise Die("malformed Go pclntab")
        return int.from_bytes(data[off : off + size], self.order)

    def _uintptr_at(self, off):
        return self._uint(self.data, off, self.ptrsize)

    def _offset_word(self, word):
        return self._uintptr_at(8 + word * self.ptrsize)

    def _data_from_word(self, word):
        off = self._offset_word(word)
        if off > len(self.data):
            raise Die("malformed Go pclntab offset")
        return self.data[off:]

    def _parse_header(self):
        if (
            len(self.data) < 16
            or self.data[4] != 0
            or self.data[5] != 0
            or self.data[6] not in (1, 2, 4)
            or self.data[7] not in (4, 8)
        ):
            raise Die("invalid Go pclntab header")

        le_magic = int.from_bytes(self.data[:4], "little")
        be_magic = int.from_bytes(self.data[:4], "big")
        if le_magic in self.MAGICS:
            self.order = "little"
            self.version = self.MAGICS[le_magic]
        elif be_magic in self.MAGICS:
            self.order = "big"
            self.version = self.MAGICS[be_magic]
        else:
            raise Die("unsupported Go pclntab magic")

        self.ptrsize = self.data[7]
        if self.version in ("ver118", "ver120"):
            self.nfunctab = self._offset_word(0)
            self.funcnametab = self._data_from_word(3)
            self.funcdata = self._data_from_word(7)
            self.functab = self.funcdata
            self.field_size = 4
        elif self.version == "ver116":
            self.nfunctab = self._offset_word(0)
            self.funcnametab = self._data_from_word(2)
            self.funcdata = self._data_from_word(6)
            self.functab = self.funcdata
            self.field_size = self.ptrsize
        else:
            self.nfunctab = self._uintptr_at(8)
            self.funcnametab = self.data
            self.funcdata = self.data
            self.functab = self.data[8 + self.ptrsize :]
            self.field_size = self.ptrsize

        size = (self.nfunctab * 2 + 1) * self.field_size
        if size > len(self.functab):
            raise Die("malformed Go functab")
        self.functab = self.functab[:size]

    def _functab_uint(self, index):
        return self._uint(self.functab, index * self.field_size, self.field_size)

    def pc(self, index):
        pc = self._functab_uint(2 * index)
        if self.version in ("ver118", "ver120"):
            pc += self.text_addr
        return pc

    def func_offset(self, index):
        return self._functab_uint(2 * index + 1)

    def func_name(self, name_off):
        return cstr(self.funcnametab, name_off)

    def name_offset(self, index):
        off = self.func_offset(index)
        first_field_size = 4 if self.version in ("ver118", "ver120") else self.ptrsize
        name_off_pos = off + first_field_size
        return self._uint(self.funcdata, name_off_pos, 4)

    def funcs(self):
        out = []
        for i in range(self.nfunctab):
            entry = self.pc(i)
            end = self.pc(i + 1)
            name = self.func_name(self.name_offset(i))
            out.append({"entry": entry, "name": name, "size": end - entry})
        return out


def find_go_pclntab_in_elf64_le(lib_path):
    data = Path(lib_path).read_bytes()
    sections = read_elf64_le_sections(data)
    text_addr = next((s["addr"] for s in sections if s["name"] == ".text"), 0)
    if text_addr == 0:
        raise Die("missing .text address")

    magics = (b"\xf1\xff\xff\xff", b"\xf0\xff\xff\xff", b"\xfa\xff\xff\xff", b"\xfb\xff\xff\xff")
    search_sections = [s for s in sections if s["name"] == ".data.rel.ro"]
    search_sections.extend(s for s in sections if s["name"] != ".data.rel.ro")
    for section in search_sections:
        blob = section["data"]
        for magic in magics:
            pos = blob.find(magic)
            if pos >= 0:
                return blob[pos:], text_addr
    raise Die("missing Go pclntab magic in ELF sections")


def find_go_func(lib_path, needle):
    pcln, text_addr = find_go_pclntab_in_elf64_le(lib_path)
    table = GoPclnTable(pcln, text_addr)
    funcs = []
    for f in table.funcs():
        if needle in f["name"]:
            f["line"] = f"0x{f['entry']:x} {f['name']} size={f['size']}"
            funcs.append(f)
    if not funcs:
        raise Die(f"function not found via Go pclntab: {needle}")
    exact = [f for f in funcs if f["name"].endswith(needle)]
    return (exact or funcs)[0]


def disassemble(lib_path, start, stop):
    p = run(["objdump", "-d", f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}", str(lib_path)])
    return p.stdout.splitlines()


def imm64_to_ascii_le(value):
    b = value.to_bytes(8, "little", signed=False)
    printable = set(bytes(string.printable, "ascii")) - {0x0b, 0x0c}
    if all(ch in printable and chr(ch) not in "\r\n\t" for ch in b):
        return b
    return None


def extract_arm64_movk_constants(lines):
    regs = {}
    constants = []
    for line in lines:
        m = re.search(r"\bmov\s+(x[0-9]+),\s*#(\d+)", line)
        if m:
            regs[m.group(1)] = int(m.group(2)) & 0xffff
            continue
        m = re.search(r"\bmovk\s+(x[0-9]+),\s*#(\d+),\s*lsl\s*#(\d+)", line)
        if not m:
            continue
        reg = m.group(1)
        if reg not in regs:
            continue
        imm = int(m.group(2)) & 0xffff
        shift = int(m.group(3))
        regs[reg] = (regs[reg] & ~(0xffff << shift)) | (imm << shift)
        if shift == 48:
            b = imm64_to_ascii_le(regs[reg])
            if b is not None:
                constants.append({"line": line.strip(), "bytes": b})
    if len(constants) < 4:
        detail = "\n".join("  " + x.strip() for x in lines[:120])
        raise Die("fewer than four printable arm64 mov/movk constants were found.\n" + detail)
    return constants[:4]


def main(argv):
    ap = argparse.ArgumentParser(description="Extract mihomo AES KEY/IV from Android APK libclash.so.")
    ap.add_argument("apk", help="path to APK")
    ap.add_argument("--abi", default="arm64-v8a", help="APK ABI to inspect, default: arm64-v8a")
    args = ap.parse_args(argv)

    apk = Path(os.path.expanduser(args.apk)).resolve()
    if not apk.is_file():
        raise Die(f"APK not found: {apk}")

    with tempfile.TemporaryDirectory(prefix="mihomo-apk-") as td:
        print("[1/4] extracting libclash.so")
        lib = extract_lib(apk, args.abi, td)
        print(f"      {lib}")

        print("[2/4] checking mihomo convert symbols")
        symbols = check_mihomo_symbols(lib)
        for s in symbols:
            if "DecodeAESBase" in s or "aesDecryptCBC" in s:
                print(f"      {s}")

        print("[3/4] locating DecodeAESBase64 with Go pclntab")
        fn = find_go_func(lib, "convert.DecodeAESBase64")
        aes = find_go_func(lib, "convert.aesDecryptCBC")
        print(f"      {fn['line']}")
        print(f"      {aes['line']}")

        print("[4/4] extracting arm64 prologue constants")
        lines = disassemble(lib, fn["entry"], fn["entry"] + min(fn["size"], 512))
        constants = extract_arm64_movk_constants(lines)
        for i, c in enumerate(constants, 1):
            print(f"      imm{i}: {c['bytes']!r}    {c['line']}")

    key = constants[0]["bytes"] + constants[1]["bytes"]
    iv = constants[2]["bytes"] + constants[3]["bytes"]
    print()
    print(f"AES-128-CBC KEY ascii: {key.decode('ascii')}")
    print(f"AES-128-CBC IV  ascii: {iv.decode('ascii')}")
    print(f"AES-128-CBC KEY hex:   {key.hex()}")
    print(f"AES-128-CBC IV  hex:   {iv.hex()}")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Die as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
