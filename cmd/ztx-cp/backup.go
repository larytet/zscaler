package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	newKeyFile := fs.String("new-master-key-file", "", "rekey: file holding the new master key")
	keyFile := fs.String("master-key-file", "", "restore: file holding the master key if the data is encrypted (or ZTX_MASTER_KEY)")
	switch args[0] {
	case "gen-master-key":
		fmt.Println(seal.Generate())
		return true
	case "rekey":
		fs.Parse(args[1:])
		old, err := masterKey(*keyFile)
		check(err)
		nk, err := masterKey(*newKeyFile)
		check(err)
		if old == nil || nk == nil || *newKeyFile == "" {
			check(fmt.Errorf("rekey needs the current key (-master-key-file or ZTX_MASTER_KEY) and the new one (-new-master-key-file)"))
		}
		n, err := rekey(*data, old, nk)
		check(err)
		fmt.Printf("%d files now encrypted with the new key. Start the control plane with the new key; old backups still need the old key, so keep it until they are replaced.\n", n)
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

// rekey re-encrypts the three private files with a new master key. A file that already opens with the new
// key is left alone, so running it again after an interruption finishes the job. Each file is replaced
// atomically and checked by reading it back before the next one is touched. Stop the control plane first.
func rekey(dir string, old, nk *seal.Key) (int, error) {
	n := 0
	for _, f := range []string{"ca.key", "policy.key", "store.json"} {
		p := filepath.Join(dir, f)
		raw, err := os.ReadFile(p)
		if err != nil {
			return n, err
		}
		if !seal.IsSealed(raw) {
			return n, fmt.Errorf("%s is not encrypted: start the control plane with the key once to encrypt it, or it was never encrypted", p)
		}
		if _, err := nk.Open(f, raw); err == nil {
			n++ // already done by an earlier run
			continue
		}
		plain, err := old.Open(f, raw)
		if err != nil {
			return n, fmt.Errorf("%s: %w", p, err)
		}
		if err := seal.Write(p, plain, nk); err != nil {
			return n, err
		}
		back, err := seal.Read(p, nk)
		if err != nil || string(back) != string(plain) {
			return n, fmt.Errorf("%s: the new file does not read back; restore it from a backup", p)
		}
		n++
	}
	return n, nil
}
