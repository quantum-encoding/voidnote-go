//go:build live

// Live round trip against voidnote.net (creates real anonymous notes).
//
//	VOIDNOTE_LIVE_IN=in.json VOIDNOTE_LIVE_OUT=out.json go test -tags live -run TestLive -v
//
// VOIDNOTE_LIVE_IN holds notes another SDK created; this test reads them
// (cross-language), then creates its own and writes them to VOIDNOTE_LIVE_OUT.
package voidnote

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type liveNotes struct {
	From          string `json:"from"`
	Password      string `json:"password"`
	SHA256        string `json:"sha256"`
	ContentSHA256 string `json:"content_sha256"`
	PBKDF2        string `json:"pbkdf2"`
	ContentPBKDF2 string `json:"content_pbkdf2"`
}

func TestLive(t *testing.T) {
	const lang, password = "go", "pässwörd-日本🔑"
	base := os.Getenv("VOIDNOTE_BASE")
	pass := func(step string) { t.Logf("PASS %s: %s", lang, step) }

	if in := os.Getenv("VOIDNOTE_LIVE_IN"); in != "" {
		if raw, err := os.ReadFile(in); err == nil {
			var prev liveNotes
			if err := json.Unmarshal(raw, &prev); err != nil {
				t.Fatal(err)
			}
			a, err := ReadWith(prev.SHA256, ReadOptions{Base: base})
			if err != nil {
				t.Fatal(err)
			}
			if a.Content != prev.ContentSHA256 || a.Kdf != KdfSHA256 || !a.Destroyed {
				t.Fatalf("%+v", a)
			}
			pass("read " + prev.From + " sha256 note (cross-language), destroyed on last view")
			b, err := ReadWith(prev.PBKDF2, ReadOptions{Password: prev.Password, Base: base})
			if err != nil {
				t.Fatal(err)
			}
			if b.Content != prev.ContentPBKDF2 || b.Kdf != KdfPBKDF2 || !b.Destroyed {
				t.Fatalf("%+v", b)
			}
			pass("read " + prev.From + " pbkdf2 note with non-ASCII password (cross-language)")
		}
	}

	out := liveNotes{From: lang, Password: password}

	out.ContentSHA256 = "live sha256 from " + lang + " — ✓ 日本"
	s, err := Create(out.ContentSHA256, CreateOptions{MaxViews: 2, Base: base})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Peek(s.URL, base)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Exists || m.Kdf != KdfSHA256 || m.ViewsRemaining != 2 || s.Kdf != KdfSHA256 {
		t.Fatalf("%+v %+v", s, m)
	}
	r, err := ReadWith(s.URL, ReadOptions{Base: base})
	if err != nil {
		t.Fatal(err)
	}
	if r.Content != out.ContentSHA256 || r.ViewsRemaining != 1 {
		t.Fatalf("%+v", r)
	}
	out.SHA256 = s.URL
	pass("anonymous sha256 create → peek → read")

	out.ContentPBKDF2 = "live pbkdf2 from " + lang + " — 🔒"
	p, err := Create(out.ContentPBKDF2, CreateOptions{Password: password, MaxViews: 2, Base: base})
	if err != nil {
		t.Fatal(err)
	}
	if m, err := Peek(p.URL, base); err != nil || m.Kdf != KdfPBKDF2 || p.Kdf != KdfPBKDF2 {
		t.Fatalf("%v %+v", err, m)
	}
	if _, err := ReadWith(p.URL, ReadOptions{Base: base}); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("want ErrPasswordRequired, got %v", err)
	}
	if m, err := Peek(p.URL, base); err != nil || m.ViewsRemaining != 2 {
		t.Fatalf("%v %+v", err, m)
	}
	pass("pbkdf2 read without password refused before consume (views still 2)")
	r, err = ReadWith(p.URL, ReadOptions{Password: password, Base: base})
	if err != nil {
		t.Fatal(err)
	}
	if r.Content != out.ContentPBKDF2 || r.ViewsRemaining != 1 {
		t.Fatalf("%+v", r)
	}
	out.PBKDF2 = p.URL
	pass("anonymous pbkdf2 create → read with non-ASCII password")

	_, err = Create("x", CreateOptions{APIKey: "vn_invalid_live_check", Base: base})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 401 || !strings.Contains(apiErr.Message, "Invalid API key.") {
		t.Fatalf("want 401 Invalid API key., got %v", err)
	}
	pass(`invalid API key surfaces 401 "Invalid API key."`)

	if dst := os.Getenv("VOIDNOTE_LIVE_OUT"); dst != "" {
		raw, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(dst, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
