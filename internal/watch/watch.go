// SPDX-License-Identifier: AGPL-3.0-only

// Package watch polls a directory for downloaded reports, hands each to a
// callback once its size is stable, and moves the source to done/ or failed/.
package watch

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Result is what the callback reports for one file.
type Result struct {
	OK   bool
	Hash string // dedupe key; empty when nothing decrypted
}

// Watcher scans Dir every Interval.
type Watcher struct {
	Dir      string
	Interval time.Duration
	// Process handles one file. It is called once per stable file.
	Process func(path string) Result

	sizes map[string]int64
	seen  map[string]bool
}

const seenFile = ".seen"

// Run blocks until ctx is done.
func (w *Watcher) Run(ctx context.Context) error {
	w.sizes = map[string]int64{}
	w.seen = loadSeen(filepath.Join(w.Dir, seenFile))
	for _, d := range []string{"done", "failed"} {
		if err := os.MkdirAll(filepath.Join(w.Dir, d), 0o700); err != nil {
			return err
		}
	}
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		w.Scan()
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Scan runs one pass. Exposed for tests.
func (w *Watcher) Scan() {
	ents, err := os.ReadDir(w.Dir)
	if err != nil {
		return
	}
	present := map[string]bool{}
	for _, e := range ents {
		if !e.Type().IsRegular() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		path := filepath.Join(w.Dir, e.Name())
		st, err := e.Info()
		if err != nil {
			continue
		}
		present[path] = true
		prev, known := w.sizes[path]
		w.sizes[path] = st.Size()
		if !known || prev != st.Size() || st.Size() == 0 {
			continue // still being written, or first sighting
		}
		delete(w.sizes, path)
		res := w.Process(path)
		dest := "failed"
		if res.OK {
			dest = "done"
			if res.Hash != "" && !w.seen[res.Hash] {
				w.seen[res.Hash] = true
				appendSeen(filepath.Join(w.Dir, seenFile), res.Hash)
			}
		}
		move(path, filepath.Join(w.Dir, dest))
	}
	for p := range w.sizes {
		if !present[p] {
			delete(w.sizes, p)
		}
	}
}

// Seen reports whether a blob hash was already processed.
func (w *Watcher) Seen(hash string) bool { return w.seen[hash] }

func move(path, dir string) {
	dst := filepath.Join(dir, filepath.Base(path))
	for i := 2; ; i++ {
		if _, err := os.Lstat(dst); os.IsNotExist(err) {
			break
		}
		dst = filepath.Join(dir, strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))+"-"+strconv.Itoa(i)+filepath.Ext(path))
	}
	_ = os.Rename(path, dst)
}

func loadSeen(path string) map[string]bool {
	m := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			m[l] = true
		}
	}
	return m
}

func appendSeen(path, hash string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(hash + "\n")
}
