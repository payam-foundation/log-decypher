// SPDX-License-Identifier: AGPL-3.0-only

// Command decypher opens sealed reports offline. It has no network code.
//
//	decypher keygen --project NAME --keyring FILE [--pub-out FILE]
//	decypher keys list|retire --keyring FILE [FINGERPRINT]
//	decypher verify PATH... --keyring FILE
//	decypher open   PATH... --keyring FILE [--out DIR | --stdout]
//	decypher watch  DIR     --keyring FILE --out DIR [--interval 5s] [--on-report CMD]
//
// Exit codes: 0 ok, 1 usage or error, 2 nothing decrypted.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/payam-foundation/log-decypher/internal/keyring"
	"github.com/payam-foundation/log-decypher/internal/opener"
	"github.com/payam-foundation/log-decypher/internal/render"
	"github.com/payam-foundation/log-decypher/internal/source"
	"github.com/payam-foundation/log-decypher/internal/watch"
	"golang.org/x/term"
)

var version = "dev"

const maxInput = 1 << 20 // one blob; larger candidates are rejected before crypto

type cli struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	now    func() time.Time
	// pass returns the keyring passphrase; confirm asks twice (new keyring).
	pass func(confirm bool) ([]byte, error)
}

func main() {
	c := &cli{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, now: time.Now, pass: promptPass}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(c.run(ctx, os.Args[1:]))
}

func (c *cli) run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		c.usage()
		return 1
	}
	var err error
	code := 0
	switch args[0] {
	case "keygen":
		err = c.keygen(args[1:])
	case "keys":
		err = c.keys(args[1:])
	case "verify":
		code, err = c.verify(args[1:])
	case "open":
		code, err = c.open(args[1:])
	case "watch":
		err = c.watch(ctx, args[1:])
	case "version", "-version", "--version":
		fmt.Fprintln(c.stdout, "decypher", version)
	case "help", "-h", "--help":
		c.usage()
	default:
		c.usage()
		return 1
	}
	if err != nil {
		fmt.Fprintln(c.stderr, "decypher:", err)
		return 1
	}
	return code
}

func (c *cli) usage() {
	fmt.Fprint(c.stderr, `usage:
  decypher keygen --project NAME --keyring FILE [--pub-out FILE]
  decypher keys list|retire --keyring FILE [FINGERPRINT]
  decypher verify PATH... --keyring FILE
  decypher open   PATH... --keyring FILE [--out DIR | --stdout]
  decypher watch  DIR     --keyring FILE --out DIR [--interval 5s] [--on-report CMD]

PATH is a file, a directory, or - for stdin: raw blob, .eml, .mbox, Maildir, armor text.
The keyring passphrase is read from the terminal or from the file named by LD_PASSPHRASE_FILE.
`)
}

// parse splits positional arguments from flags so flags may follow paths.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	return pos, nil
}

func newFlags(name string, c *cli) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	return fs
}

func (c *cli) loadKeyring(path string) (*keyring.Keyring, error) {
	kr, _, err := c.loadKeyringPass(path)
	return kr, err
}

func (c *cli) loadKeyringPass(path string) (*keyring.Keyring, []byte, error) {
	if path == "" {
		return nil, nil, errors.New("--keyring is required")
	}
	pass, err := c.pass(false)
	if err != nil {
		return nil, nil, err
	}
	kr, err := keyring.Load(path, pass)
	return kr, pass, err
}

func (c *cli) keygen(args []string) error {
	fs := newFlags("keygen", c)
	project := fs.String("project", "", "project name: lowercase letters, digits, . _ -")
	path := fs.String("keyring", "", "keyring file (created if absent)")
	pubOut := fs.String("pub-out", "", "write the public key string to this file")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *path == "" || *project == "" {
		return errors.New("--project and --keyring are required")
	}
	// Same rule as the envelope project field, so a key can always open what it seals.
	if err := checkProject(*project); err != nil {
		return err
	}
	var kr *keyring.Keyring
	var pass []byte
	var err error
	if keyring.Exists(*path) {
		if pass, err = c.pass(false); err != nil {
			return err
		}
		if kr, err = keyring.Load(*path, pass); err != nil {
			return err
		}
	} else {
		if pass, err = c.pass(true); err != nil {
			return err
		}
		kr = &keyring.Keyring{}
	}
	// Rotation: older active keys of the same project stay usable but are marked retired.
	for _, e := range kr.Entries {
		if e.Project == *project && e.Status != keyring.StatusRetired {
			e.Status = keyring.StatusRetired
		}
	}
	e, pub, err := kr.Add(*project)
	if err != nil {
		return err
	}
	if err := kr.Save(*path, pass); err != nil {
		return err
	}
	if *pubOut != "" {
		if err := os.WriteFile(*pubOut, []byte(pub.String()+"\n"), 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(c.stdout, "project:     %s\nfingerprint: %s\npublic key:  %s\n", e.Project, e.Fingerprint, pub.String())
	return nil
}

func checkProject(p string) error {
	if p == "" || len(p) > 64 {
		return errors.New("bad project name")
	}
	for i, r := range p {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || i > 0 && (r == '.' || r == '_' || r == '-')
		if !ok {
			return errors.New("bad project name: use lowercase letters, digits, . _ -")
		}
	}
	return nil
}

func (c *cli) keys(args []string) error {
	if len(args) == 0 || (args[0] != "list" && args[0] != "retire") {
		return errors.New("usage: decypher keys list|retire --keyring FILE [FINGERPRINT]")
	}
	fs := newFlags("keys", c)
	path := fs.String("keyring", "", "keyring file")
	pos, err := parse(fs, args[1:])
	if err != nil {
		return err
	}
	kr, pass, err := c.loadKeyringPass(*path)
	if err != nil {
		return err
	}
	if args[0] == "retire" {
		if len(pos) != 1 {
			return errors.New("usage: decypher keys retire --keyring FILE FINGERPRINT")
		}
		if err := kr.Retire(pos[0]); err != nil {
			return err
		}
		return kr.Save(*path, pass)
	}
	for _, e := range kr.Entries {
		fmt.Fprintf(c.stdout, "%s  %-12s %-8s %s\n", e.Fingerprint, e.Project, e.Status, e.Created.Format("2006-01-02"))
	}
	return nil
}

// scan decrypts every candidate found under paths. fn is called per report.
func (c *cli) scan(kr *keyring.Keyring, paths []string, fn func(path string, r *opener.Report)) (opened, skipped, files int) {
	for _, p := range paths {
		for _, it := range source.Load(p, c.stdin) {
			files++
			if it.Err != nil {
				fmt.Fprintf(c.stderr, "skip %s: %v\n", it.Path, it.Err)
				skipped++
				continue
			}
			for _, b := range it.Blobs {
				if len(b) > maxInput {
					skipped++
					continue
				}
				r, err := opener.Try(kr, b, c.now())
				if err != nil {
					skipped++
					continue
				}
				opened++
				fn(it.Path, r)
			}
		}
	}
	return
}

func (c *cli) verify(args []string) (int, error) {
	fs := newFlags("verify", c)
	path := fs.String("keyring", "", "keyring file")
	paths, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	if len(paths) == 0 {
		return 1, errors.New("usage: decypher verify PATH... --keyring FILE")
	}
	kr, err := c.loadKeyring(*path)
	if err != nil {
		return 1, err
	}
	failed := 0
	for _, p := range paths {
		for _, it := range source.Load(p, c.stdin) {
			if it.Err != nil {
				fmt.Fprintf(c.stdout, "fail %s: %v\n", it.Path, it.Err)
				failed++
				continue
			}
			ok := 0
			var last error
			for _, b := range it.Blobs {
				if len(b) > maxInput {
					last = errors.New("input too large")
					continue
				}
				r, err := opener.Try(kr, b, c.now())
				if err != nil {
					last = err
					continue
				}
				ok++
				fmt.Fprintf(c.stdout, "ok %s %s %s\n", r.Env.ID, r.Env.Project, r.Fingerprint)
			}
			if ok == 0 {
				if last == nil {
					last = errors.New("no candidate blob")
				}
				fmt.Fprintf(c.stdout, "fail %s: %v\n", it.Path, last)
				failed++
			}
		}
	}
	if failed > 0 {
		return 2, nil
	}
	return 0, nil
}

func (c *cli) open(args []string) (int, error) {
	fs := newFlags("open", c)
	path := fs.String("keyring", "", "keyring file")
	out := fs.String("out", "", "output directory")
	toStdout := fs.Bool("stdout", false, "print to stdout, write nothing to disk")
	paths, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	if len(paths) == 0 || (*out == "") == !*toStdout {
		return 1, errors.New("usage: decypher open PATH... --keyring FILE (--out DIR | --stdout)")
	}
	kr, err := c.loadKeyring(*path)
	if err != nil {
		return 1, err
	}
	var werr error
	opened, skipped, _ := c.scan(kr, paths, func(_ string, r *opener.Report) {
		if *toStdout {
			fmt.Fprintln(c.stdout, render.Markdown(r.Env, r.Fingerprint))
			return
		}
		p, err := writeReport(*out, r)
		if err != nil {
			werr = err
			return
		}
		fmt.Fprintln(c.stdout, p)
	})
	fmt.Fprintf(c.stderr, "opened %d, skipped %d\n", opened, skipped)
	if werr != nil {
		return 1, werr
	}
	if opened == 0 {
		return 2, nil
	}
	return 0, nil
}

// writeReport writes OUT/<project>/<date>/<id>.md and .json (0600, dirs 0700)
// and returns the markdown path. Existing files are never overwritten.
func writeReport(out string, r *opener.Report) (string, error) {
	dir := filepath.Join(out, r.Env.Project, r.Env.Created.UTC().Format("2006-01-02"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	base := r.Env.ID
	for i := 2; exists(filepath.Join(dir, base+".md")); i++ {
		base = fmt.Sprintf("%s-%d", r.Env.ID, i)
	}
	md := filepath.Join(dir, base+".md")
	if err := writeNew(md, []byte(render.Markdown(r.Env, r.Fingerprint))); err != nil {
		return "", err
	}
	if err := writeNew(filepath.Join(dir, base+".json"), r.JSON); err != nil {
		return "", err
	}
	return md, nil
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (c *cli) watch(ctx context.Context, args []string) error {
	fs := newFlags("watch", c)
	path := fs.String("keyring", "", "keyring file")
	out := fs.String("out", "", "output directory")
	interval := fs.Duration("interval", 5*time.Second, "poll interval")
	onReport := fs.String("on-report", "", "command run with the output path as its argument")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || *out == "" || *interval <= 0 {
		return errors.New("usage: decypher watch DIR --keyring FILE --out DIR [--interval 5s] [--on-report CMD]")
	}
	kr, err := c.loadKeyring(*path)
	if err != nil {
		return err
	}
	var w *watch.Watcher
	w = &watch.Watcher{Dir: pos[0], Interval: *interval, Process: func(p string) watch.Result {
		res := watch.Result{}
		c.scan(kr, []string{p}, func(_ string, r *opener.Report) {
			if w.Seen(r.Hash) {
				res = watch.Result{OK: true} // duplicate: already opened, file goes to done/
				return
			}
			md, err := writeReport(*out, r)
			if err != nil {
				fmt.Fprintln(c.stderr, "write:", err)
				return
			}
			res = watch.Result{OK: true, Hash: r.Hash}
			fmt.Fprintf(c.stdout, "opened %s -> %s\n", r.Env.ID, md)
			if *onReport != "" {
				runHook(c.stderr, *onReport, md)
			}
		})
		return res
	}}
	fmt.Fprintf(c.stderr, "watching %s every %s\n", pos[0], *interval)
	return w.Run(ctx)
}

// runHook runs the command with the report path as its last argument. The
// command line is split on spaces; no shell is involved.
func runHook(stderr io.Writer, cmdline, path string) {
	f := strings.Fields(cmdline)
	if len(f) == 0 {
		return
	}
	cmd := exec.Command(f[0], append(f[1:], path)...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(stderr, "on-report: %v\n", err)
	}
}

// promptPass reads the passphrase from LD_PASSPHRASE_FILE or the terminal.
func promptPass(confirm bool) ([]byte, error) {
	if f := os.Getenv("LD_PASSPHRASE_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		return bytes.TrimRight(b, "\r\n"), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("no terminal: set LD_PASSPHRASE_FILE")
	}
	fmt.Fprint(os.Stderr, "keyring passphrase: ")
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "repeat passphrase: ")
		p2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(p, p2) {
			return nil, errors.New("passphrases differ")
		}
	}
	return p, nil
}
