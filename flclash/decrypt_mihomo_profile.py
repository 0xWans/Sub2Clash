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


def cstr(data, off):
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("utf-8", errors="replace")


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

    def name_offset(self, index):
        off = self.func_offset(index)
        first_field_size = 4 if self.version in ("ver118", "ver120") else self.ptrsize
        return self._uint(self.funcdata, off + first_field_size, 4)

    def funcs(self):
        funcs = []
        for i in range(self.nfunctab):
            entry = self.pc(i)
            end = self.pc(i + 1)
            name = cstr(self.funcnametab, self.name_offset(i))
            funcs.append({"entry": entry, "name": name, "size": end - entry})
        return funcs


def read_macho_header(data, off):
    if off < 0 or off + 32 > len(data):
        raise Die("invalid Mach-O header")
    magic = int.from_bytes(data[off : off + 4], "little")
    if magic == 0xFEEDFACF:
        order = "little"
    elif magic == 0xCFFAEDFE:
        order = "big"
    else:
        raise Die("not a 64-bit Mach-O slice")
    cputype = int.from_bytes(data[off + 4 : off + 8], order, signed=True)
    ncmds = int.from_bytes(data[off + 16 : off + 20], order)
    sizeofcmds = int.from_bytes(data[off + 20 : off + 24], order)
    if off + 32 + sizeofcmds > len(data):
        raise Die("invalid Mach-O load command table")
    return order, cputype, ncmds


def macho_arch_slices(data):
    magic = int.from_bytes(data[:4], "big")
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        if len(data) < 8:
            raise Die("invalid fat Mach-O header")
        nfat_arch = int.from_bytes(data[4:8], "big")
        stride = 32 if magic == 0xCAFEBABF else 20
        slices = []
        for i in range(nfat_arch):
            off = 8 + i * stride
            if off + stride > len(data):
                raise Die("invalid fat Mach-O arch table")
            cputype = int.from_bytes(data[off : off + 4], "big", signed=True)
            offset_size = 8 if stride == 32 else 4
            slice_off = int.from_bytes(data[off + 8 : off + 8 + offset_size], "big")
            slice_size = int.from_bytes(
                data[off + 8 + offset_size : off + 8 + offset_size * 2], "big"
            )
            if slice_off + slice_size > len(data):
                raise Die("invalid fat Mach-O slice")
            slices.append({"cputype": cputype, "off": slice_off, "size": slice_size})
        return slices

    order, cputype, _ = read_macho_header(data, 0)
    return [{"cputype": cputype, "off": 0, "size": len(data), "order": order}]


def wanted_macho_cpu(arch):
    if arch == "x86_64":
        return 0x01000007
    if arch == "arm64":
        return 0x0100000C
    raise Die(f"unsupported arch: {arch}")


def find_macho_section_data(binary, arch, sectname):
    data = Path(binary).read_bytes()
    want = wanted_macho_cpu(arch)
    slice_info = next((s for s in macho_arch_slices(data) if s["cputype"] == want), None)
    if slice_info is None:
        raise Die(f"{arch} slice not found")

    slice_off = slice_info["off"]
    order, _, ncmds = read_macho_header(data, slice_off)
    cursor = slice_off + 32
    text_addr = 0
    pcln = None
    for _ in range(ncmds):
        if cursor + 8 > len(data):
            raise Die("invalid Mach-O load command")
        cmd = int.from_bytes(data[cursor : cursor + 4], order)
        cmdsize = int.from_bytes(data[cursor + 4 : cursor + 8], order)
        if cmdsize < 8 or cursor + cmdsize > len(data):
            raise Die("invalid Mach-O load command size")
        if cmd == 0x19:
            nsects = int.from_bytes(data[cursor + 64 : cursor + 68], order)
            sect_off = cursor + 72
            for i in range(nsects):
                s = sect_off + i * 80
                if s + 80 > cursor + cmdsize:
                    raise Die("invalid Mach-O section table")
                name = data[s : s + 16].split(b"\x00", 1)[0].decode("ascii", errors="replace")
                segment = data[s + 16 : s + 32].split(b"\x00", 1)[0].decode(
                    "ascii", errors="replace"
                )
                addr = int.from_bytes(data[s + 32 : s + 40], order)
                size = int.from_bytes(data[s + 40 : s + 48], order)
                offset = int.from_bytes(data[s + 48 : s + 52], order)
                if name == "__text":
                    text_addr = addr
                if name == sectname:
                    start = slice_off + offset
                    end = start + size
                    if end > len(data):
                        raise Die("invalid Mach-O section data")
                    pcln = data[start:end]
        cursor += cmdsize

    if text_addr == 0 or not pcln:
        raise Die(f"missing {sectname} or __text")
    return pcln, text_addr


def find_funcs(binary, needle, arch):
    pcln, text_addr = find_macho_section_data(binary, arch, "__gopclntab")
    table = GoPclnTable(pcln, text_addr)
    funcs = []
    for f in table.funcs():
        if needle in f["name"]:
            f["line"] = f"0x{f['entry']:x} {f['name']} size={f['size']}"
            funcs.append(f)
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


def find_mihomo_binary(root):
    candidates = []
    for path in Path(root).rglob("*"):
        if not path.is_file():
            continue
        try:
            with path.open("rb") as f:
                head = f.read(4)
        except OSError:
            continue
        if head in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
            candidates.append(path)

    matches = []
    for path in candidates:
        try:
            symbols = check_mihomo_symbols(path)
        except Die:
            continue
        matches.append((path, symbols))

    if not matches:
        raise Die(f"no Mach-O binary with mihomo convert symbols found under: {root}")
    matches.sort(key=lambda x: ("/Contents/MacOS/" not in str(x[0]), len(str(x[0]))))
    return matches[0]


def resolve_binary(input_path, temp_dir):
    path = Path(os.path.expanduser(input_path)).resolve()
    if not path.is_file():
        raise Die(f"input not found: {path}")
    if path.suffix.lower() != ".pkg":
        return str(path), None

    extract_dir = Path(temp_dir) / "pkg"
    run(["pkgutil", "--expand-full", str(path), str(extract_dir)])
    binary, symbols = find_mihomo_binary(extract_dir)
    return str(binary), symbols


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
        description="Extract or use mihomo/Clash.Meta fork AES-base64 profile KEY/IV."
    )
    ap.add_argument("input", help="path to macOS .pkg or Clash/mihomo core Mach-O binary")
    ap.add_argument("encrypted", nargs="?", help="path to the encrypted profile YAML")
    ap.add_argument("output", nargs="?", help="path for decrypted YAML output")
    ap.add_argument("--arch", choices=("x86_64", "arm64"), default="x86_64")
    ap.add_argument(
        "--max-instructions",
        type=int,
        default=100,
        help="number of function instructions to inspect from DecodeAESBase64",
    )
    args = ap.parse_args(argv)
    if (args.encrypted is None) != (args.output is None):
        ap.error("encrypted and output must be provided together")

    encrypted = os.path.abspath(os.path.expanduser(args.encrypted)) if args.encrypted else None
    output = os.path.abspath(os.path.expanduser(args.output)) if args.output else None
    if encrypted and not os.path.isfile(encrypted):
        raise Die(f"encrypted profile not found: {encrypted}")

    decrypting = encrypted is not None
    total_steps = 5 if decrypting else 4
    with tempfile.TemporaryDirectory(prefix="mihomo-profile-") as td:
        print(f"[1/{total_steps}] resolving input")
        binary, symbols = resolve_binary(args.input, td)
        print(f"      {binary}")

        print(f"[2/{total_steps}] checking mihomo convert symbols")
        if symbols is None:
            symbols = check_mihomo_symbols(binary)
        for s in symbols:
            print(f"      {s}")

        print(f"[3/{total_steps}] locating convert.DecodeAESBase64 with Mach-O Go pclntab")
        fn, constants, key, iv, lines = get_key_iv(binary, args.arch, args.max_instructions)
        print(f"      {fn['line']}")

        print(f"[4/{total_steps}] derived AES material")
        for i, c in enumerate(constants, 1):
            print(f"      imm{i}: {c['bytes']!r}    {c['line']}")
        print(f"      AES-128-CBC KEY ascii: {key.decode('ascii')}")
        print(f"      AES-128-CBC IV  ascii: {iv.decode('ascii')}")
        print(f"      AES-128-CBC KEY hex:   {key.hex()}")
        print(f"      AES-128-CBC IV  hex:   {iv.hex()}")

        if not decrypting:
            return

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
