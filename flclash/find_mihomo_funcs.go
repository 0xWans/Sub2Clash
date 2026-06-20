package main

import (
	"debug/macho"
	"debug/gosym"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <mach-o> <func-substring>\n", os.Args[0])
		os.Exit(2)
	}

	var f *macho.File
	if fat, err := macho.OpenFat(os.Args[1]); err == nil {
		for i := range fat.Arches {
			if fat.Arches[i].Cpu == macho.CpuAmd64 {
				f = fat.Arches[i].File
				break
			}
		}
		if f == nil {
			fmt.Fprintln(os.Stderr, "x86_64 slice not found")
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
