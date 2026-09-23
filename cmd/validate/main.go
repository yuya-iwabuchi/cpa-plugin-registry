// Command validate checks a CLIProxyAPI plugin registry file, and with -live
// the GitHub releases its entries install from.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/yuya-iwabuchi/cpa-plugin-registry/internal/registry"
)

func main() {
	live := flag.Bool("live", false, "also check each github-release entry's latest release on GitHub")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "usage: validate [-live] registry.json")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	os.Exit(run(flag.Arg(0), *live))
}

func run(file string, live bool) int {
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	reg, errs := registry.Check(data)
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
	}
	if len(errs) > 0 {
		return 1
	}
	if !live {
		fmt.Printf("OK: %s: %d plugin(s) valid\n", file, len(reg.Plugins))
		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	releases := registry.Releases{
		Client:  &http.Client{Timeout: 2 * time.Minute},
		APIBase: "https://api.github.com",
		Token:   os.Getenv("GITHUB_TOKEN"),
	}
	failed := 0
	for i, p := range reg.Plugins {
		if p.InstallType() != registry.InstallGitHubRelease {
			fmt.Printf("%s: skipped (%s install)\n", p.ID, p.InstallType())
			continue
		}
		for _, err := range releases.Check(ctx, os.Stdout, p) {
			fmt.Fprintf(os.Stderr, "%s: %v\n", registry.Label(i, p.ID), err)
			failed++
		}
	}
	if failed > 0 {
		return 1
	}
	fmt.Printf("OK: %s: %d plugin(s) valid; latest releases install on %d platforms\n", file, len(reg.Plugins), len(registry.Platforms))
	return 0
}
