package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/larytet/zscaler/internal/backup"
	"github.com/larytet/zscaler/internal/cli"
	"github.com/larytet/zscaler/internal/seal"
)

// runBackupCommand handles `ztx-cp backup`, `ztx-cp verify-backup` and `ztx-cp restore`. It reports whether
// the first argument was one of them.
func runBackupCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	data := fs.String("data", "cp-data", "control plane data directory")
	file := fs.String("file", "", "the backup file")
	force := fs.Bool("force", false, "restore: move an existing data directory aside and restore anyway")
	keyFile := fs.String("master-key-file", "", "restore: file holding the master key if the data is encrypted (or ZTX_MASTER_KEY)")
	switch args[0] {
	case "gen-master-key":
		fmt.Println(seal.Generate())
		return true
	case "backup", "verify-backup", "restore":
	default:
		return false
	}
	fs.Parse(args[1:])
	if *file == "" {
		fmt.Fprintln(os.Stderr, "-file is required")
		os.Exit(2)
	}
	now := time.Now()
	switch args[0] {
	case "backup":
		m, err := backup.Create(*data, *file, now, version)
		check(err)
		fmt.Printf("backup written to %s (%d files, mode 0600).\nIt holds the CA private keys, the signing key and every tenant secret in clear: store it like the keys.\n", *file, len(m.Files))
	case "verify-backup":
		m, err := backup.Verify(*file)
		check(err)
		fmt.Printf("ok: %d files, made %s by version %s; every checksum matches\n", len(m.Files), m.Created.Format(time.RFC3339), m.Version)
	case "restore":
		key, err := masterKey(*keyFile)
		check(err)
		m, moved, err := backup.Restore(*file, *data, *force, now, key)
		check(err)
		fmt.Printf("restored %d files into %s (made %s).\n", len(m.Files), *data, m.Created.Format(time.RFC3339))
		if moved != "" {
			fmt.Printf("the previous data was moved to %s; delete it when you no longer need it\n", moved)
		}
		fmt.Println("start the control plane; devices keep their certificates because the CA key came back with it.")
	}
	return true
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// masterKey reads the master key from a file or ZTX_MASTER_KEY; no key at all is allowed and gives nil.
func masterKey(file string) (*seal.Key, error) {
	v, err := cli.Secret(file, "ZTX_MASTER_KEY")
	if err != nil || v == "" {
		return nil, err
	}
	return seal.ParseKey(v)
}
