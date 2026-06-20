package main

import (
	"debug/gosym"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

func cstr(b []byte, off uint32) string {
	i := int(off)
	j := i
	for j < len(b) && b[j] != 0 {
		j++
	}
	if i < 0 || i >= len(b) {
		return ""
	}
	return string(b[i:j])
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <elf64-le> <func-substring>\n", os.Args[0])
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(data) < 64 || string(data[:4]) != "\x7fELF" || data[4] != 2 || data[5] != 1 {
		fmt.Fprintln(os.Stderr, "not an ELF64 little-endian file")
		os.Exit(1)
	}

	bo := binary.LittleEndian
	shoff := bo.Uint64(data[40:48])
	shentsize := bo.Uint16(data[58:60])
	shnum := bo.Uint16(data[60:62])
	shstrndx := bo.Uint16(data[62:64])
	if shoff == 0 || shentsize == 0 || shnum == 0 || shstrndx >= shnum {
		fmt.Fprintln(os.Stderr, "invalid section table")
		os.Exit(1)
	}

	section := func(i uint16) []byte {
		start := int(shoff) + int(i)*int(shentsize)
		end := start + int(shentsize)
		if start < 0 || end > len(data) {
			return nil
		}
		return data[start:end]
	}

	shstr := section(shstrndx)
	if shstr == nil {
		fmt.Fprintln(os.Stderr, "invalid shstrtab section")
		os.Exit(1)
	}
	shstrOff := bo.Uint64(shstr[24:32])
	shstrSize := bo.Uint64(shstr[32:40])
	if int(shstrOff+shstrSize) > len(data) {
		fmt.Fprintln(os.Stderr, "invalid shstrtab data")
		os.Exit(1)
	}
	names := data[shstrOff : shstrOff+shstrSize]

	var textAddr uint64
	var pcl []byte
	for i := uint16(0); i < shnum; i++ {
		s := section(i)
		if s == nil {
			continue
		}
		name := cstr(names, bo.Uint32(s[0:4]))
		addr := bo.Uint64(s[16:24])
		off := bo.Uint64(s[24:32])
		size := bo.Uint64(s[32:40])
		if name == ".text" {
			textAddr = addr
		}
		if name == ".data.rel.ro" {
			if int(off+size) <= len(data) {
				blob := data[off : off+size]
				magic := []byte{0xf1, 0xff, 0xff, 0xff}
				for pos := 0; pos+4 <= len(blob); pos++ {
					if string(blob[pos:pos+4]) == string(magic) {
						pcl = blob[pos:]
						break
					}
				}
			}
		}
	}
	if textAddr == 0 || len(pcl) == 0 {
		fmt.Fprintln(os.Stderr, "missing .text address or Go pclntab magic in .data.rel.ro")
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
