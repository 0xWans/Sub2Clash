#!/usr/bin/env python3
import argparse
import base64
import binascii
import os
import re
import string
import subprocess
import sys
import tempfile
from pathlib import Path


GO_FIND_FUNCS = r'''
package main

import (
	"debug/gosym"
	"debug/macho"
	"fmt"
	"os"
	"strings"
)

func wantedCPU(arch string) macho.Cpu {
	switch arch {
	case "x86_64", "amd64":
		return macho.CpuAmd64
	case "arm64", "aarch64":
		return macho.CpuArm64
	default:
		return 0
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s <mach-o> <func-substring> <arch>\n", os.Args[0])
		os.Exit(2)
	}

	var f *macho.File
	want := wantedCPU(os.Args[3])
	if want == 0 {
		fmt.Fprintf(os.Stderr, "unsupported arch: %s\n", os.Args[3])
		os.Exit(2)
	}

	if fat, err := macho.OpenFat(os.Args[1]); err == nil {
		for i := range fat.Arches {
			if fat.Arches[i].Cpu == want {
				f = fat.Arches[i].File
				break
			}
		}
		if f == nil {
			fmt.Fprintf(os.Stderr, "%s slice not found\n", os.Args[3])
			os.Exit(1)
		}
	} else {
		var err error
		f, err = macho.Open(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	var pcl []byte
	var textAddr uint64
	for _, s := range f.Sections {
		if s.Name == "__gopclntab" {
			var err error
			pcl, err = s.Data()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		if s.Name == "__text" {
			textAddr = s.Addr
		}
	}
	if len(pcl) == 0 || textAddr == 0 {
		fmt.Fprintln(os.Stderr, "missing __gopclntab or __text")
		os.Exit(1)
	}

	lt := gosym.NewLineTable(pcl, textAddr)
	t, err := gosym.NewTable(nil, lt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, fn := range t.Funcs {
		if strings.Contains(fn.Name, os.Args[2]) {
			fmt.Printf("0x%x %s size=%d\n", fn.Entry, fn.Name, fn.End-fn.Entry)
		}
	}
}
'''


class Die(Exception):
    pass


def run(cmd, *, check=True, text=True):
    try:
        p = subprocess.run(cmd, check=False, capture_output=True, text=text)
    except FileNotFoundError as e:
        raise Die(f"missing command: {cmd[0]}") from e
    if check and p.returncode != 0:
        stderr = p.stderr.strip() if text else p.stderr.decode(errors="replace").strip()
        stdout = p.stdout.strip() if text else p.stdout.decode(errors="replace").strip()
        msg = stderr or stdout or f"exit {p.returncode}"
        raise Die(f"{' '.join(cmd)} failed: {msg}")
    return p


def check_mihomo_symbols(binary):
    p = run(
        ["grep", "-oaE", r"metacubex/mihomo/common/convert\.[A-Za-z]+", binary],
        check=False,
    )
    if p.returncode not in (0, 1):
        raise Die(p.stderr.strip() or "grep failed")
    symbols = sorted(set(x.strip() for x in p.stdout.splitlines() if x.strip()))
    if not symbols:
        data = Path(binary).read_bytes()
        rx = rb"metacubex/mihomo/common/convert\.[A-Za-z0-9]+"
        symbols = sorted(set(m.group(0).decode("ascii") for m in re.finditer(rx, data)))

    # The required grep regex is intentionally [A-Za-z]+, so DecodeAESBase64
    # appears as DecodeAESBase in grep output because digits are not matched.
    has_decode = any(s.endswith((".DecodeAESBase", ".DecodeAESBase64")) for s in symbols)
    has_aes = any(s.endswith(".aesDecryptCBC") for s in symbols)
    if not (has_decode and has_aes):
        found = "\n".join(f"  {s}" for s in symbols[:40]) or "  <none>"
        raise Die(
            "mihomo convert DecodeAESBase/aesDecryptCBC symbols were not found; "
            "this workflow does not apply.\n"
            f"scanned convert symbols:\n{found}"
        )
    return symbols


def find_funcs(binary, needle, arch):
    with tempfile.TemporaryDirectory(prefix="mihomo-find-") as td:
        helper = Path(td) / "find.go"
        helper.write_text(GO_FIND_FUNCS)
        p = run(["go", "run", str(helper), binary, needle, arch])
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
    return funcs


def choose_func(funcs, exact_suffix):
    exact = [f for f in funcs if f["name"].endswith(exact_suffix)]
    if len(exact) == 1:
        return exact[0]
    if not funcs:
        raise Die(f"function not found: {exact_suffix}")
    if len(exact) > 1:
        return sorted(exact, key=lambda f: f["size"], reverse=True)[0]
    return sorted(funcs, key=lambda f: f["size"], reverse=True)[0]


def disassemble(binary, arch):
    p = run(["otool", "-arch", arch, "-tvV", binary])
    return p.stdout.splitlines()


def line_addr(line):
    m = re.match(r"^\s*([0-9a-fA-F]{8,16})\s+", line)
    return int(m.group(1), 16) if m else None


def function_window(lines, entry, size, max_instructions):
    in_func = []
    end = entry + size if size > 0 else None
    started = False
    for line in lines:
        addr = line_addr(line)
        if addr is None:
            continue
        if not started:
            if addr == entry:
                started = True
            else:
                continue
        if end is not None and addr >= end:
            break
        in_func.append(line)
        if len(in_func) >= max_instructions:
            break
    if not in_func:
        raise Die(f"could not find disassembly line for function VA 0x{entry:x}")
    return in_func


def imm64_to_ascii_le(value):
    b = value.to_bytes(8, "little", signed=False)
    printable = set(bytes(string.printable, "ascii")) - {0x0b, 0x0c}
    if all(ch in printable and chr(ch) not in "\r\n\t" for ch in b):
        return b
    return None


def extract_x86_constants(lines):
    candidates = []
    for i, line in enumerate(lines):
        if "movabsq" not in line:
            continue
        m = re.search(r"\$0x([0-9a-fA-F]{1,16})", line)
        if not m:
            continue
        b = imm64_to_ascii_le(int(m.group(1), 16))
        if b is None:
            continue
        next_line = lines[i + 1] if i + 1 < len(lines) else ""
        candidates.append({"line": line.strip(), "bytes": b, "next": next_line.strip()})
    if len(candidates) < 4:
        detail = "\n".join("  " + x.strip() for x in lines[:80])
        raise Die(
            "fewer than four printable movabsq imm64 constants were found in the prologue.\n"
            + detail
        )
    return candidates[:4]


def parse_arm_imm(token):
    token = token.strip().lstrip("#")
    base = 16 if token.startswith(("0x", "0X")) else 10
    return int(token, base)


def extract_arm64_constants(lines):
    regs = {}
    candidates = []
    for line in lines:
        m = re.search(r"\bmov\s+(x[0-9]+),\s*#?((?:0x)?[0-9a-fA-F]+)", line)
        if m:
            regs[m.group(1)] = parse_arm_imm(m.group(2))
            continue
        m = re.search(
            r"\bmovk\s+(x[0-9]+),\s*#?((?:0x)?[0-9a-fA-F]+),\s*lsl\s*#?(\d+)",
            line,
        )
        if m and m.group(1) in regs:
            reg = m.group(1)
            imm = parse_arm_imm(m.group(2)) & 0xffff
            shift = int(m.group(3))
            regs[reg] = (regs[reg] & ~(0xffff << shift)) | (imm << shift)
            if shift == 48:
                b = imm64_to_ascii_le(regs[reg])
                if b is not None:
                    candidates.append({"line": line.strip(), "bytes": b, "next": ""})
    if len(candidates) < 4:
        detail = "\n".join("  " + x.strip() for x in lines[:120])
        raise Die(
            "fewer than four printable arm64 mov/movk imm64 constants were found.\n"
            + detail
        )
    return candidates[:4]


def get_key_iv(binary, arch, max_instructions):
    funcs = find_funcs(binary, "convert.DecodeAESBase64", arch)
    fn = choose_func(funcs, ".DecodeAESBase64")
    lines = function_window(disassemble(binary, arch), fn["entry"], fn["size"], max_instructions)
    if arch == "x86_64":
        constants = extract_x86_constants(lines)
    elif arch == "arm64":
        constants = extract_arm64_constants(lines)
    else:
        raise Die(f"unsupported arch: {arch}")
    key = constants[0]["bytes"] + constants[1]["bytes"]
    iv = constants[2]["bytes"] + constants[3]["bytes"]
    if len(key) != 16 or len(iv) != 16:
        raise Die("extracted KEY/IV are not 16 bytes each")
    return fn, constants, key, iv, lines


def load_aes_backend():
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        return AES, unpad, "pycryptodome"
    except Exception:
        pass

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        def decrypt(ciphertext, key, iv):
            decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()

        def unpad_pkcs7(data, block_size):
            if not data:
                raise ValueError("empty plaintext")
            pad = data[-1]
            if pad < 1 or pad > block_size:
                raise ValueError("bad padding")
            if data[-pad:] != bytes([pad]) * pad:
                raise ValueError("bad padding")
            return data[:-pad]

        class AESCompat:
            MODE_CBC = object()

            @staticmethod
            def new(key, mode, iv):
                class C:
                    def decrypt(self, ciphertext):
                        return decrypt(ciphertext, key, iv)

                return C()

        return AESCompat, unpad_pkcs7, "cryptography"
    except Exception:
        pass

    raise Die("missing AES backend: install pycryptodome or cryptography for Python 3")


def is_base64ish(data):
    allowed = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n\t ")
    return all(ch in allowed for ch in data)


def decrypt_profile(enc_path, out_path, key, iv):
    raw = Path(enc_path).read_bytes().strip()
    if not is_base64ish(raw):
        raise Die(
            "encrypted file is not pure base64 characters; the client may wrap the payload first."
        )
    AES, unpad, backend = load_aes_backend()
    try:
        outer = base64.b64decode(raw, validate=False)
        pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(outer), 16)
    except (binascii.Error, ValueError) as e:
        raise Die(f"AES/base64 decrypt failed: {e}") from e

    try:
        out = base64.b64decode(pt, validate=True)
    except Exception:
        out = pt

    Path(out_path).write_bytes(out)
    return out, backend


def validate_yaml(data):
    stripped = data.lstrip()
    prefixes = (b"mixed-port:", b"port:", b"proxies:", b"rules:")
    prefix_ok = any(stripped.startswith(p) for p in prefixes)
    size_ok = 10 * 1024 <= len(data) <= 1024 * 1024

    yaml_ok = None
    yaml_error = None
    try:
        import yaml

        yaml.safe_load(data.decode("utf-8"))
        yaml_ok = True
    except ImportError:
        yaml_ok = None
        yaml_error = "PyYAML is not installed; skipped yaml.safe_load"
    except Exception as e:
        yaml_ok = False
        yaml_error = str(e)

    return prefix_ok, size_ok, yaml_ok, yaml_error


def main(argv):
    ap = argparse.ArgumentParser(
        description="Decrypt mihomo/Clash.Meta fork AES-base64 profile YAML."
    )
    ap.add_argument("binary", help="path to the macOS Clash/mihomo core Mach-O binary")
    ap.add_argument("encrypted", help="path to the encrypted profile YAML")
    ap.add_argument("output", help="path for decrypted YAML output")
    ap.add_argument("--arch", choices=("x86_64", "arm64"), default="x86_64")
    ap.add_argument(
        "--max-instructions",
        type=int,
        default=100,
        help="number of function instructions to inspect from DecodeAESBase64",
    )
    args = ap.parse_args(argv)

    binary = os.path.abspath(os.path.expanduser(args.binary))
    encrypted = os.path.abspath(os.path.expanduser(args.encrypted))
    output = os.path.abspath(os.path.expanduser(args.output))

    for path, label in ((binary, "binary"), (encrypted, "encrypted profile")):
        if not os.path.isfile(path):
            raise Die(f"{label} not found: {path}")

    print("[1/5] checking mihomo convert symbols")
    symbols = check_mihomo_symbols(binary)
    for s in symbols:
        print(f"      {s}")

    print("[2/5] locating convert.DecodeAESBase64 with Go debug/macho + gosym")
    fn, constants, key, iv, lines = get_key_iv(binary, args.arch, args.max_instructions)
    print(f"      {fn['line']}")

    print("[3/5] extracting prologue constants")
    for i, c in enumerate(constants, 1):
        print(f"      imm{i}: {c['bytes']!r}    {c['line']}")

    print("[4/5] derived AES material")
    print(f"      AES-128-CBC KEY ascii: {key.decode('ascii')}")
    print(f"      AES-128-CBC IV  ascii: {iv.decode('ascii')}")
    print(f"      AES-128-CBC KEY hex:   {key.hex()}")
    print(f"      AES-128-CBC IV  hex:   {iv.hex()}")

    print("[5/5] decrypting and validating output")
    data, backend = decrypt_profile(encrypted, output, key, iv)
    prefix_ok, size_ok, yaml_ok, yaml_error = validate_yaml(data)
    print(f"      AES backend: {backend}")
    print(f"      wrote: {output}")
    print(f"      size: {len(data)} bytes")
    print(f"      starts with Clash YAML key: {prefix_ok}")
    print(f"      size 10KB-1MB: {size_ok}")
    if yaml_ok is True:
        print("      yaml.safe_load: ok")
    elif yaml_ok is False:
        print(f"      yaml.safe_load: failed: {yaml_error}")
    else:
        print(f"      yaml.safe_load: skipped: {yaml_error}")

    if not prefix_ok or yaml_ok is False:
        raise Die(
            "decrypted output did not pass acceptance checks; check imm64 byte order or KEY/IV order."
        )


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Die as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
