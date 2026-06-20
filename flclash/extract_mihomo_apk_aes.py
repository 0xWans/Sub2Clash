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


def find_go_func(lib_path, helper, needle):
    p = run(["go", "run", str(helper), str(lib_path), needle])
    funcs = []
    for line in p.stdout.splitlines():
        m = re.match(r"0x([0-9a-fA-F]+)\s+(\S+)\s+size=(\d+)", line.strip())
        if m:
            funcs.append(
                {
                    "entry": int(m.group(1), 16),
                    "name": m.group(2),
                    "size": int(m.group(3)),
                    "line": line.strip(),
                }
            )
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
    ap.add_argument(
        "--helper",
        default="find_go_funcs_elf64_raw.go",
        help="Go helper used to parse ELF64 Go pclntab",
    )
    args = ap.parse_args(argv)

    apk = Path(os.path.expanduser(args.apk)).resolve()
    helper = Path(args.helper).resolve()
    if not apk.is_file():
        raise Die(f"APK not found: {apk}")
    if not helper.is_file():
        raise Die(f"helper not found: {helper}")

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
        fn = find_go_func(lib, helper, "convert.DecodeAESBase64")
        aes = find_go_func(lib, helper, "convert.aesDecryptCBC")
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
