// SPDX-License-Identifier: AGPL-3.0-only

// Package source turns files the operator downloaded (raw blobs, .eml, .mbox,
// Maildir directories, armored text) into candidate blobs. Nothing here
// decides whether a candidate is valid; the keyring does.
package source

import (
	"bytes"
	"encoding/base64"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/payam-foundation/log-decypher/armor"
	"github.com/payam-foundation/log-decypher/seal"
)

const (
	// MaxFile bounds one input file. Mail with attachments can exceed one blob.
	MaxFile  = 64 << 20
	maxDepth = 5
)

// Item is one input file and the candidate blobs found in it.
type Item struct {
	Path  string
	Blobs [][]byte
	Err   error
}

var reMailHdr = regexp.MustCompile(`^(From |[A-Za-z][A-Za-z0-9-]*:)`)

// Load reads path (a file or a directory, walked recursively) or stdin when
// path is "-". Unreadable or oversized files are reported in Item.Err.
func Load(path string, stdin io.Reader) []Item {
	if path == "-" {
		b, err := io.ReadAll(io.LimitReader(stdin, MaxFile+1))
		it := Item{Path: "-"}
		if err == nil && len(b) > MaxFile {
			err = fs.ErrInvalid
		}
		if err != nil {
			it.Err = err
		} else {
			it.Blobs = Extract(b)
		}
		return []Item{it}
	}
	st, err := os.Stat(path)
	if err != nil {
		return []Item{{Path: path, Err: err}}
	}
	if !st.IsDir() {
		return []Item{loadFile(path)}
	}
	var out []Item
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			out = append(out, Item{Path: p, Err: err})
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		out = append(out, loadFile(p))
		return nil
	})
	return out
}

func loadFile(path string) Item {
	f, err := os.Open(path)
	if err != nil {
		return Item{Path: path, Err: err}
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if err != nil {
		return Item{Path: path, Err: err}
	}
	if len(b) > MaxFile {
		return Item{Path: path, Err: fs.ErrInvalid}
	}
	return Item{Path: path, Blobs: Extract(b)}
}

// Extract returns candidate blobs from raw file contents.
func Extract(data []byte) [][]byte {
	var out [][]byte
	add := func(b []byte) {
		if len(b) > 0 && len(b) <= seal.MaxBlob {
			out = append(out, b)
		}
	}
	if !reMailHdr.Match(firstLine(data)) {
		if b, err := armor.Decode(string(data)); err == nil {
			add(b)
		}
		add(data)
		return out
	}
	for _, msg := range splitMbox(data) {
		walkMail(msg, 0, add)
	}
	if len(out) == 0 {
		// Looked like mail but yielded nothing; it may be armored text or a
		// raw blob whose first bytes happen to resemble a header.
		if b, err := armor.Decode(string(data)); err == nil {
			add(b)
		}
		add(data)
	}
	return out
}

func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return bytes.TrimRight(b[:i], "\r")
	}
	return b
}

// splitMbox splits an mbox on "From " separator lines. A file without one is a
// single message (.eml).
func splitMbox(b []byte) [][]byte {
	if !bytes.HasPrefix(b, []byte("From ")) {
		return [][]byte{b}
	}
	var msgs [][]byte
	start := -1
	prevBlank := true // a separator is "From " at file start or after a blank line
	for i := 0; i < len(b); {
		end := len(b)
		if j := bytes.IndexByte(b[i:], '\n'); j >= 0 {
			end = i + j + 1
		}
		line := b[i:end]
		if prevBlank && bytes.HasPrefix(line, []byte("From ")) {
			if start >= 0 {
				msgs = append(msgs, b[start:i])
			}
			start = end
		}
		prevBlank = len(bytes.TrimRight(line, "\r\n")) == 0
		i = end
	}
	if start >= 0 {
		msgs = append(msgs, b[start:])
	}
	return msgs
}

func walkMail(raw []byte, depth int, add func([]byte)) {
	if depth > maxDepth {
		return
	}
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return
	}
	walkPart(hdrs(m.Header), m.Body, depth, add)
}

type hdrs map[string][]string

func (t hdrs) get(k string) string {
	if v := t[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func walkPart(h hdrs, body io.Reader, depth int, add func([]byte)) {
	if depth > maxDepth {
		return
	}
	ct, params, err := mime.ParseMediaType(h.get("Content-Type"))
	if err != nil {
		ct = "text/plain"
	}
	if strings.HasPrefix(ct, "multipart/") && params["boundary"] != "" {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				return
			}
			walkPart(hdrs(p.Header), p, depth+1, add)
		}
	}
	data, err := io.ReadAll(io.LimitReader(decodeCTE(h.get("Content-Transfer-Encoding"), body), MaxFile))
	if err != nil {
		return
	}
	switch {
	case ct == "message/rfc822":
		walkMail(data, depth+1, add)
	case strings.HasPrefix(ct, "text/"):
		if b, err := armor.Decode(string(data)); err == nil {
			add(b)
		}
	default:
		add(data)
		if b, err := armor.Decode(string(data)); err == nil {
			add(b)
		}
	}
}

func decodeCTE(enc string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	}
	return r
}
