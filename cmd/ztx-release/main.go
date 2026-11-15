// ztx-release builds a release (reproducible binaries, checksums, a bill of materials, a signature) and
// verifies one. See RELEASE.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/larytet/zscaler/internal/logx"
	"github.com/larytet/zscaler/internal/release"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ztx-release keygen|build|verify [flags]")
		os.Exit(2)
	}
	logx.Setup("ztx-release")
	switch os.Args[1] {
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		out := fs.String("out", "release-key", "write <out>.pub and <out>.key")
		fs.Parse(os.Args[2:])
		pub, priv, err := release.Keygen()
		if err != nil {
			logx.Die(err)
		}
		if err := os.WriteFile(*out+".pub", pub, 0o644); err != nil {
			logx.Die(err)
		}
		if err := os.WriteFile(*out+".key", priv, 0o600); err != nil {
			logx.Die(err)
		}
		fmt.Printf("wrote %s.pub (publish it) and %s.key (keep it secret: a secret store or an HSM, not the repository)\n", *out, *out)
	case "build":
		fs := flag.NewFlagSet("build", flag.ExitOnError)
		root := fs.String("root", ".", "source tree")
		out := fs.String("out", "dist", "output directory")
		version := fs.String("version", "", "version to stamp, for example v0.2.0 (required)")
		key := fs.String("key", "", "ed25519 private key file to sign the checksums with (optional)")
		only := fs.String("only", "", "comma-separated programs to build, for example ztx-agent,ztx-connector (default all)")
		fs.Parse(os.Args[2:])
		var targets []release.Target
		for _, t := range release.Targets {
			if *only == "" || strings.Contains(","+*only+",", ","+t.Cmd+",") {
				targets = append(targets, t)
			}
		}
		files, err := release.Build(release.Options{Root: *root, Out: *out, Version: *version, Targets: targets})
		if err != nil {
			logx.Die(err)
		}
		var priv []byte
		if *key != "" {
			if priv, err = os.ReadFile(*key); err != nil {
				logx.Die(err)
			}
		}
		if err := release.Finish(*out, files, *version, priv); err != nil {
			logx.Die(err)
		}
		fmt.Printf("built %d files in %s", len(files), *out)
		if priv == nil {
			fmt.Print(" (not signed: no --key)")
		}
		fmt.Println()
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		dir := fs.String("dir", "dist", "release directory")
		pub := fs.String("pub", "release-key.pub", "public key file")
		fs.Parse(os.Args[2:])
		pb, err := os.ReadFile(*pub)
		if err != nil {
			logx.Die(err)
		}
		if problems := release.Verify(*dir, pb); len(problems) > 0 {
			for _, p := range problems {
				fmt.Println("PROBLEM:", p)
			}
			os.Exit(1)
		}
		fmt.Println("ok: the signature, the checksums and the bill of materials agree with the files")
	default:
		fmt.Fprintln(os.Stderr, "usage: ztx-release keygen|build|verify [flags]")
		os.Exit(2)
	}
}
