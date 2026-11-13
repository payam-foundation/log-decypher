// SPDX-License-Identifier: AGPL-3.0-only

package watch

import (
	"os"
	"path/filepath"
	"testing"
)

func newWatcher(t *testing.T, dir string, proc func(string) Result) *Watcher {
	t.Helper()
	w := &Watcher{Dir: dir, Process: proc, sizes: map[string]int64{}, seen: map[string]bool{}}
	for _, d := range []string{"done", "failed"} {
		os.MkdirAll(filepath.Join(dir, d), 0o700)
	}
	return w
}

func TestStableSizeThenDoneOrFailed(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	w := newWatcher(t, dir, func(p string) Result {
		calls++
		if filepath.Base(p) == "bad.dat" {
			return Result{}
		}
		return Result{OK: true, Hash: "h1"}
	})
	good, bad := filepath.Join(dir, "good.dat"), filepath.Join(dir, "bad.dat")
	os.WriteFile(good, []byte("aaaa"), 0o600)
	os.WriteFile(bad, []byte("bbbb"), 0o600)
	w.Scan() // first sighting
	if calls != 0 {
		t.Fatal("processed on first sighting")
	}
	os.WriteFile(good, []byte("aaaaaaaa"), 0o600) // slow writer: size changed
	w.Scan()
	if calls != 1 || !exists(good) {
		t.Fatalf("calls=%d; growing file must wait", calls)
	}
	w.Scan()
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
	if !exists(filepath.Join(dir, "done", "good.dat")) || !exists(filepath.Join(dir, "failed", "bad.dat")) {
		t.Fatal("files not moved")
	}
	if !w.Seen("h1") {
		t.Fatal("hash not recorded")
	}
	if loadSeen(filepath.Join(dir, seenFile))["h1"] != true {
		t.Fatal(".seen not persisted")
	}
}

func TestDuplicateNameDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	w := newWatcher(t, dir, func(string) Result { return Result{OK: true} })
	for i := 0; i < 2; i++ {
		os.WriteFile(filepath.Join(dir, "r.dat"), []byte("x"), 0o600)
		w.Scan()
		w.Scan()
	}
	if !exists(filepath.Join(dir, "done", "r.dat")) || !exists(filepath.Join(dir, "done", "r-2.dat")) {
		t.Fatal("second file overwrote the first")
	}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }
