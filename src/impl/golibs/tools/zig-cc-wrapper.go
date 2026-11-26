// zig-cc-wrapper adapts Go's GCC-oriented CGO arguments for Zig's MSVC target.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	zig := os.Getenv("PORTWEAVER_ZIG")
	if zig == "" {
		fmt.Fprintln(os.Stderr, "zig-cc-wrapper: missing Zig executable")
		os.Exit(2)
	}
	name := filepath.Base(os.Args[0])
	if strings.EqualFold(name, "ar") || strings.EqualFold(name, "ar.exe") {
		run(zig, append([]string{"ar"}, os.Args[1:]...))
		return
	}
	if len(os.Args) < 2 || (os.Args[1] != "cc" && os.Args[1] != "c++") {
		fmt.Fprintln(os.Stderr, "usage: zig-cc-wrapper <cc|c++> [arguments...]")
		os.Exit(2)
	}
	target := os.Getenv("PORTWEAVER_ZIG_TARGET")
	if target == "" {
		fmt.Fprintln(os.Stderr, "zig-cc-wrapper: missing target")
		os.Exit(2)
	}
	args := append([]string{os.Args[1], "-target", target}, filterArgs(os.Args[2:])...)
	run(zig, args)
}

func run(zig string, args []string) {
	cmd := exec.Command(zig, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "zig-cc-wrapper: %v\n", err)
		os.Exit(1)
	}
}

func filterArgs(input []string) []string {
	args := make([]string, 0, len(input))
	for _, arg := range input {
		if arg != "-mthreads" {
			args = append(args, arg)
		}
	}
	return args
}
