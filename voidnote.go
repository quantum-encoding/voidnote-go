// Package voidnote is the official Go SDK for VoidNote.
//
// Zero-knowledge self-destructing notes. The key lives in the link. We never see it.
//
// Usage:
//
//	// Create a note — no account needed (v1 API: client-side encryption, server-generated tokenId)
//	result, err := voidnote.Create("my secret", voidnote.CreateOptions{})
//	fmt.Println(result.URL)   // https://voidnote.net/n/{tokenId}#{secret}
//
//	// Read and decrypt (auto-detects v1 and legacy URL formats)
//	note, err := voidnote.Read("https://voidnote.net/n/TOKEN#SECRET")
//	fmt.Println(note.Content)
//
//	// Password-protected note
//	result, err = voidnote.Create("my secret", voidnote.CreateOptions{Password: "correct horse"})
//	note, err = voidnote.ReadWith(result.URL, voidnote.ReadOptions{Password: "correct horse"})
package voidnote

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultBase = "https://voidnote.net"

// Key derivations a note may declare. The AES key comes from the 32-hex secret in the link:
//
//	KdfSHA256: key = SHA-256(secret bytes)
//	KdfPBKDF2: key = PBKDF2-HMAC-SHA256(password UTF-8, salt = secret bytes, 600000 iterations)
const (
	KdfSHA256 = "sha256"
	KdfPBKDF2 = "pbkdf2-sha256-600k"

	PBKDF2Iterations = 600_000
)

var (
	// ErrNotFound: the note does not exist, expired, or its views are used up.
	ErrNotFound = errors.New("voidnote: note not found, expired or already destroyed")
	// ErrPasswordRequired: the note was created with a password and none was given. No view was used.
	ErrPasswordRequired = errors.New("voidnote: this note needs a password — set ReadOptions.Password (no view was used)")
	// ErrUnsupportedKdf: the note uses a key derivation this SDK version cannot do. No view was used.
	ErrUnsupportedKdf = errors.New("voidnote: unsupported key derivation")
	// ErrDecryption: the password or the link's key is wrong. The view was used.
	ErrDecryption = errors.New("voidnote: decryption failed")
)

// APIError is an HTTP failure reported by the server, with its error message.
type APIError struct {
	Op         string
	StatusCode int
	Message    string
	// RetryAfter is how long the server asked the client to wait (429), zero when it did not say.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("voidnote: %s: HTTP %d", e.Op, e.StatusCode)
	if e.Message != "" {
		s += " — " + e.Message
	}
	if e.RetryAfter > 0 {
		s += fmt.Sprintf(" (retry after %s)", e.RetryAfter)
	}
	return s
}

// ReadResult holds the decrypted content of a note.
type ReadResult struct {
	Content        string
	Title          string
	ViewsRemaining int
	Destroyed      bool
	Kdf            string // v1 notes: KdfSHA256 or KdfPBKDF2
	ViewCount      int    // views used, including this one
	MaxViews       int
}

// CreateOptions configures how a new note is created.
type CreateOptions struct {
	APIKey    string // optional: vn_... from a free account. Empty creates an anonymous note.
	Password  string // optional: the reader needs it as well as the link (KdfPBKDF2)
	MaxViews  int    // defaults to 1; up to 10 anonymous, 100 with an API key
	ExpiresIn int    // hours, defaults to 1; up to 168 anonymous, 720 with an API key
	Base      string // optional: override API base URL
}

// CreateResult holds the shareable link for a newly created note.
type CreateResult struct {
	URL       string // full shareable URL — includes #secret for v1 notes
	Token     string // 32-char tokenId
	ExpiresAt string
	ViewLimit int
	Kdf       string
}

// ReadOptions configures ReadWith.
type ReadOptions struct {
	Password string // for notes created with a password; ignored for notes without one
	Base     string // optional: override API base URL
}

// PeekResult holds metadata about a note without consuming a view.
// Kdf is KdfPBKDF2 when the note needs a password.
type PeekResult struct {
	Exists         bool
	Type           string
	CreatedAt      string
	ExpiresAt      string
	ViewLimit      int
	ViewsRemaining int
	Kdf            string
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

// parsedURL holds the result of parsing a note URL.
type parsedURL struct {
	isV1      bool
	tokenID   string // 32-char
	secret    string // 32-char (v1 only)
	fullToken string // 64-char (legacy only)
}

// parseNoteURL detects v1 (tokenId#secret) and legacy (64-char path) URL formats.
func parseNoteURL(input string) (parsedURL, error) {
	// v1: contains #secret
	if beforeHash, secret, found := strings.Cut(input, "#"); found {
		beforeHash = strings.TrimSuffix(beforeHash, "/")
		parts := strings.Split(beforeHash, "/")
		tokenID := parts[len(parts)-1]
		if isHex32(tokenID) && isHex32(secret) {
			return parsedURL{isV1: true, tokenID: strings.ToLower(tokenID), secret: strings.ToLower(secret)}, nil
		}
	}
	// Legacy: 64-char hex in URL path
	token := extractLegacyToken(input)
	if len(token) == 64 {
		return parsedURL{isV1: false, fullToken: token}, nil
	}
	return parsedURL{}, fmt.Errorf("voidnote: invalid URL — expected .../tokenId#secret or 64-char token")
}

func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// retryAfter parses a Retry-After header: delta-seconds or an HTTP date.
func retryAfter(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		if d := time.Until(at).Round(time.Second); d > 0 {
			return d
		}
	}
	return 0
}

// apiError reports an HTTP failure with the server's error message when it sent one.
func apiError(op string, status int, header http.Header, body []byte) error {
	var payload struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &payload) == nil && payload.Error != "" {
		msg = payload.Error
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return &APIError{Op: op, StatusCode: status, Message: msg, RetryAfter: retryAfter(header)}
}

// doJSON sends req and decodes a 2xx JSON body into out; other statuses become *APIError.
func doJSON(op string, req *http.Request, out any) error {
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("voidnote: %s failed: %w", op, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("voidnote: %s: reading response: %w", op, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return apiError(op, resp.StatusCode, resp.Header, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("voidnote: %s: parsing response: %w", op, err)
	}
	return nil
}

func getJSON(op, url string, out any) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("voidnote: %s: building request: %w", op, err)
	}
	return doJSON(op, req, out)
}

// checkKdf maps an absent kdf to KdfSHA256 and rejects ones this SDK cannot derive.
func checkKdf(kdf string) (string, error) {
	switch kdf {
	case "", KdfSHA256:
		return KdfSHA256, nil
	case KdfPBKDF2:
		return KdfPBKDF2, nil
	}
	return "", fmt.Errorf("%w %q — upgrade voidnote-go", ErrUnsupportedKdf, kdf)
}

// Read fetches and decrypts a VoidNote.
// urlOrToken may be a v1 URL (https://voidnote.net/n/tokenId#secret),
// a legacy URL (https://voidnote.net/note/<64-token>), or a raw 64-char token.
func Read(urlOrToken string) (*ReadResult, error) {
	return ReadWith(urlOrToken, ReadOptions{})
}

// ReadFrom is like Read but allows overriding the base URL.
func ReadFrom(urlOrToken, base string) (*ReadResult, error) {
	return ReadWith(urlOrToken, ReadOptions{Base: base})
}

// ReadWith is like Read with a password for notes created with one.
//
// v1 notes are checked first without using a view: a missing note returns
// ErrNotFound, a note that needs a password when none was given returns
// ErrPasswordRequired, and an unknown key derivation returns ErrUnsupportedKdf,
// all with the view unused. A wrong password (ErrDecryption) is only detectable
// after the view is used.
func ReadWith(urlOrToken string, opts ReadOptions) (*ReadResult, error) {
	base := opts.Base
	if base == "" {
		base = defaultBase
	}

	parsed, err := parseNoteURL(urlOrToken)
	if err != nil {
		return nil, err
	}

	if parsed.isV1 {
		return readV1(parsed.tokenID, parsed.secret, base, opts.Password)
	}
	return readLegacy(parsed.fullToken, base)
}

// readV1 checks the note's metadata, calls the v1 consume endpoint and decrypts client-side.
func readV1(tokenID, secret, base, password string) (*ReadResult, error) {
	var meta struct {
		Exists    bool   `json:"exists"`
		ViewLimit int    `json:"viewLimit"`
		Kdf       string `json:"kdf"`
	}
	if err := getJSON("read", base+"/api/v1/note/"+tokenID+"/meta/", &meta); err != nil {
		return nil, err
	}
	if !meta.Exists {
		return nil, ErrNotFound
	}
	metaKdf, err := checkKdf(meta.Kdf)
	if err != nil {
		return nil, err
	}
	if metaKdf != KdfSHA256 && password == "" {
		return nil, ErrPasswordRequired
	}

	var payload struct {
		Encrypted      string `json:"encrypted"`
		IV             string `json:"iv"`
		ViewsRemaining int    `json:"viewsRemaining"`
		Destroyed      bool   `json:"destroyed"`
		Kdf            string `json:"kdf"`
	}
	if err := getJSON("read", base+"/api/v1/note/"+tokenID+"/consume/", &payload); err != nil {
		return nil, err
	}
	kdf := metaKdf
	if payload.Kdf != "" {
		if kdf, err = checkKdf(payload.Kdf); err != nil {
			return nil, err
		}
	}

	key, err := noteKey(secret, kdf, password)
	if err != nil {
		return nil, err
	}
	content, err := decryptWithKey(payload.Encrypted, payload.IV, key)
	if err != nil {
		if kdf == KdfSHA256 {
			return nil, fmt.Errorf("%w: the link's key is wrong or incomplete", ErrDecryption)
		}
		return nil, fmt.Errorf("%w: wrong password (this read used a view)", ErrDecryption)
	}

	maxViews := meta.ViewLimit
	if maxViews == 0 {
		maxViews = payload.ViewsRemaining + 1
	}
	return &ReadResult{
		Content:        content,
		ViewsRemaining: payload.ViewsRemaining,
		Destroyed:      payload.Destroyed,
		Kdf:            kdf,
		ViewCount:      maxViews - payload.ViewsRemaining,
		MaxViews:       maxViews,
	}, nil
}

// readLegacy calls the old server-decrypt endpoint (backward compat).
func readLegacy(fullToken, base string) (*ReadResult, error) {
	var payload struct {
		Content   string `json:"content"`
		Title     string `json:"title"`
		ViewCount int    `json:"viewCount"`
		MaxViews  int    `json:"maxViews"`
		Destroyed bool   `json:"destroyed"`
	}
	if err := getJSON("read", base+"/api/note/"+fullToken+"/", &payload); err != nil {
		return nil, err
	}
	return &ReadResult{
		Content:   payload.Content,
		Title:     payload.Title,
		ViewCount: payload.ViewCount,
		MaxViews:  payload.MaxViews,
		Destroyed: payload.Destroyed,
	}, nil
}

// Peek fetches note metadata without consuming a view.
func Peek(urlOrToken string, base ...string) (*PeekResult, error) {
	apiBase := defaultBase
	if len(base) > 0 && base[0] != "" {
		apiBase = base[0]
	}

	// Extract 32-char tokenId from the URL (before any # fragment)
	withoutFragment, _, _ := strings.Cut(urlOrToken, "#")
	parts := strings.Split(strings.TrimSuffix(withoutFragment, "/"), "/")
	tokenID := parts[len(parts)-1]
	if len(tokenID) == 64 {
		tokenID = tokenID[:32] // legacy: take first half
	}
	if !isHex32(tokenID) {
		return nil, fmt.Errorf("voidnote: cannot extract tokenId from input")
	}

	var result struct {
		Exists         bool   `json:"exists"`
		Type           string `json:"type"`
		CreatedAt      string `json:"createdAt"`
		ExpiresAt      string `json:"expiresAt"`
		ViewLimit      int    `json:"viewLimit"`
		ViewsRemaining int    `json:"viewsRemaining"`
		Kdf            string `json:"kdf"`
	}
	if err := getJSON("peek", apiBase+"/api/v1/note/"+strings.ToLower(tokenID)+"/meta/", &result); err != nil {
		return nil, err
	}
	return &PeekResult{
		Exists:         result.Exists,
		Type:           result.Type,
		CreatedAt:      result.CreatedAt,
		ExpiresAt:      result.ExpiresAt,
		ViewLimit:      result.ViewLimit,
		ViewsRemaining: result.ViewsRemaining,
		Kdf:            result.Kdf,
	}, nil
}

// Create encrypts content client-side and stores a new note on VoidNote using the v1 API.
// The server generates the tokenId. The client holds the secret in the URL fragment.
// The returned URL is https://voidnote.net/n/{tokenId}#{secret} — share the full URL.
//
// No API key is needed: without one the note is anonymous, held to 168 hours and
// 10 views, and rate-limited per IP. With a Password the key is derived with
// PBKDF2 and the reader needs both the link and the password. Server refusals
// (limits, rate limiting) return *APIError with the server's message and RetryAfter.
func Create(content string, opts CreateOptions) (*CreateResult, error) {
	if opts.MaxViews == 0 {
		opts.MaxViews = 1
	}
	if opts.ExpiresIn == 0 {
		opts.ExpiresIn = 1 // default 1 hour
	}
	if opts.MaxViews < 0 || opts.ExpiresIn < 0 {
		return nil, fmt.Errorf("voidnote: MaxViews and ExpiresIn must be positive")
	}
	if opts.Base == "" {
		opts.Base = defaultBase
	}
	kdf := KdfSHA256
	if opts.Password != "" {
		kdf = KdfPBKDF2
	}

	// Generate secret only — server generates tokenId
	secretBytes := make([]byte, 16)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("voidnote: generating secret: %w", err)
	}
	secret := hex.EncodeToString(secretBytes)

	key, err := noteKey(secret, kdf, opts.Password)
	if err != nil {
		return nil, err
	}
	encryptedContent, iv, err := encryptWithKey(content, key)
	if err != nil {
		return nil, fmt.Errorf("voidnote: encryption failed: %w", err)
	}

	reqBody, _ := json.Marshal(map[string]any{
		"encrypted": encryptedContent,
		"iv":        iv,
		"expiresIn": opts.ExpiresIn * 3600, // hours → seconds
		"viewLimit": opts.MaxViews,
		"kdf":       kdf,
	})

	req, err := http.NewRequest("POST", opts.Base+"/api/v1/note/", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("voidnote: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if opts.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+opts.APIKey)
	}

	var result struct {
		Token     string `json:"token"`
		URL       string `json:"url"`
		ExpiresAt string `json:"expiresAt"`
		ViewLimit int    `json:"viewLimit"`
		Kdf       string `json:"kdf"`
	}
	if err := doJSON("create", req, &result); err != nil {
		return nil, err
	}
	if result.ViewLimit == 0 {
		result.ViewLimit = opts.MaxViews
	}
	if result.Kdf == "" {
		result.Kdf = kdf
	}

	// Append #secret to make the full shareable URL
	return &CreateResult{
		URL:       result.URL + "#" + secret,
		Token:     result.Token,
		ExpiresAt: result.ExpiresAt,
		ViewLimit: result.ViewLimit,
		Kdf:       result.Kdf,
	}, nil
}

// ---------------------------------------------------------------------------
// Void Stream — live encrypted real-time channels
// ---------------------------------------------------------------------------

// StreamOptions configures a new Void Stream.
type StreamOptions struct {
	APIKey string
	Title  string
	TTL    int // 3600 (1h), 21600 (6h), or 86400 (24h) — defaults to 3600
	Base   string
}

// StreamHandle is a live Void Stream. Write and Close authenticate with the
// API key the stream was created (or resumed) with.
type StreamHandle struct {
	URL       string
	ExpiresAt string
	fullToken string
	secret    string
	base      string
	apiKey    string
}

// WatchEvent is a single decrypted message from a stream. A non-nil Err with an
// empty Content reports a terminal failure; the channel is closed after it.
type WatchEvent struct {
	Content string
	Err     error
}

// WatchOptions configures WatchWith.
type WatchOptions struct {
	Password string // for password-protected streams
	Base     string
}

// CreateStream creates a new Void Stream. Requires an API key from a free account.
func CreateStream(opts StreamOptions) (*StreamHandle, error) {
	if opts.APIKey == "" {
		return nil, fmt.Errorf("voidnote: APIKey is required")
	}
	if opts.TTL == 0 {
		opts.TTL = 3600
	}
	if opts.Base == "" {
		opts.Base = defaultBase
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("voidnote: generating token: %w", err)
	}
	fullToken := hex.EncodeToString(raw)
	tokenID := fullToken[:32]

	reqBody, _ := json.Marshal(map[string]any{
		"tokenId": tokenID,
		"title":   opts.Title,
		"ttl":     opts.TTL,
	})
	req, _ := http.NewRequest("POST", opts.Base+"/api/stream/", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+opts.APIKey)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("voidnote: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, apiError("create stream", resp.StatusCode, resp.Header, body)
	}

	var result struct {
		SiteURL   string `json:"siteUrl"`
		ExpiresAt string `json:"expiresAt"`
	}
	json.Unmarshal(body, &result)

	return &StreamHandle{
		URL:       result.SiteURL + "/stream/" + fullToken,
		ExpiresAt: result.ExpiresAt,
		fullToken: fullToken,
		secret:    fullToken[32:],
		base:      opts.Base,
		apiKey:    opts.APIKey,
	}, nil
}

// post sends an authenticated JSON POST to one of the stream's endpoints.
func (s *StreamHandle) post(op, endpoint string, body []byte) error {
	if len(s.fullToken) != 64 {
		return fmt.Errorf("voidnote: %s: invalid stream token (want 64 hex chars)", op)
	}
	if s.apiKey == "" {
		return fmt.Errorf("voidnote: %s: API key required to write to or close a broadcast stream (use ResumeStreamWithKey)", op)
	}
	req, _ := http.NewRequest("POST", s.base+"/api/stream/"+s.fullToken+"/"+endpoint+"/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("voidnote: %s failed: %w", op, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return apiError(op, resp.StatusCode, resp.Header, respBody)
	}
	return nil
}

// Write encrypts content and pushes it to the stream.
func (s *StreamHandle) Write(content string) error {
	encryptedContent, iv, err := encrypt(content, s.secret)
	if err != nil {
		return fmt.Errorf("voidnote: encryption failed: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"encryptedContent": encryptedContent, "iv": iv})
	return s.post("write", "write", body)
}

// Close marks the stream as closed. All content self-destructs.
func (s *StreamHandle) Close() error {
	return s.post("close", "close", []byte("{}"))
}

// ResumeStream reconstructs a StreamHandle from a full 64-char token or URL.
// The handle has no API key, so Write and Close return an error; use
// ResumeStreamWithKey to keep writing to a stream you created.
func ResumeStream(urlOrToken string, base ...string) *StreamHandle {
	return ResumeStreamWithKey(urlOrToken, "", base...)
}

// ResumeStreamWithKey reconstructs a StreamHandle that can Write and Close,
// authenticated with the API key of the stream's creator.
func ResumeStreamWithKey(urlOrToken, apiKey string, base ...string) *StreamHandle {
	apiBase := defaultBase
	if len(base) > 0 && base[0] != "" {
		apiBase = base[0]
	}
	token := strings.ToLower(extractLegacyToken(urlOrToken))
	secret := ""
	if len(token) == 64 {
		secret = token[32:]
	}
	return &StreamHandle{
		URL:       apiBase + "/stream/" + token,
		fullToken: token,
		secret:    secret,
		base:      apiBase,
		apiKey:    apiKey,
	}
}

// errStreamEnded marks a join refused because the stream already closed or expired.
var errStreamEnded = fmt.Errorf("voidnote: stream has ended")

// joinStream obtains an access token for reading a stream's events.
func joinStream(ctx context.Context, apiBase, token, password string) (string, error) {
	payload := map[string]string{}
	if password != "" {
		payload["password"] = password
	}
	reqBody, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", apiBase+"/api/stream/"+token+"/join/", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("voidnote: join failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusGone {
		return "", errStreamEnded
	}
	if resp.StatusCode != 200 {
		return "", apiError("join", resp.StatusCode, resp.Header, body)
	}
	var result struct {
		AccessToken string `json:"accessToken"`
	}
	if json.Unmarshal(body, &result) != nil || result.AccessToken == "" {
		return "", fmt.Errorf("voidnote: join returned no access token")
	}
	return result.AccessToken, nil
}

// watchMaxRetries is how many consecutive network failures Watch tolerates
// while reconnecting before it reports the error and stops.
const watchMaxRetries = 5

// Watch subscribes to a Void Stream and returns a channel of decrypted messages.
func Watch(ctx context.Context, urlOrToken string, base ...string) (<-chan WatchEvent, error) {
	opts := WatchOptions{}
	if len(base) > 0 {
		opts.Base = base[0]
	}
	return WatchWith(ctx, urlOrToken, opts)
}

// WatchWith subscribes to a Void Stream (optionally password-protected). It joins
// the stream for an access token, re-joining when the token expires, and
// reconnects with Last-Event-ID until the stream closes or expires. HTTP errors
// and repeated network failures arrive as a final WatchEvent with Err set.
func WatchWith(ctx context.Context, urlOrToken string, opts WatchOptions) (<-chan WatchEvent, error) {
	apiBase := defaultBase
	if opts.Base != "" {
		apiBase = opts.Base
	}

	token := strings.ToLower(extractLegacyToken(urlOrToken))
	if len(token) != 64 {
		return nil, fmt.Errorf("voidnote: invalid token length %d (want 64)", len(token))
	}
	secret := token[32:]
	key := deriveKey(secret)

	accessToken, err := joinStream(ctx, apiBase, token, opts.Password)
	if err != nil && err != errStreamEnded {
		return nil, err
	}

	ch := make(chan WatchEvent, 32)
	if err == errStreamEnded {
		close(ch)
		return ch, nil
	}

	fail := func(err error) {
		select {
		case ch <- WatchEvent{Err: err}:
		case <-ctx.Done():
		}
	}

	go func() {
		defer close(ch)
		lastID := ""
		rejoined := false
		failures := 0
		client := &http.Client{}

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			eventsURL := apiBase + "/api/stream/" + token + "/events/?at=" + url.QueryEscape(accessToken)
			req, err := http.NewRequestWithContext(ctx, "GET", eventsURL, nil)
			if err != nil {
				fail(err)
				return
			}
			if lastID != "" {
				req.Header.Set("Last-Event-ID", lastID)
			}

			resp, err := client.Do(req)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				failures++
				if failures > watchMaxRetries {
					fail(fmt.Errorf("voidnote: watch: %w", err))
					return
				}
				time.Sleep(time.Duration(1<<failures) * time.Second)
				continue
			}

			// Access tokens live 30 minutes: re-join once, then give up on a repeat 401.
			if resp.StatusCode == http.StatusUnauthorized && !rejoined {
				resp.Body.Close()
				accessToken, err = joinStream(ctx, apiBase, token, opts.Password)
				if err == errStreamEnded {
					return
				}
				if err != nil {
					fail(err)
					return
				}
				rejoined = true
				continue
			}
			if resp.StatusCode != 200 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				fail(apiError("watch", resp.StatusCode, resp.Header, body))
				return
			}
			rejoined = false
			failures = 0

			scanner := bufio.NewScanner(resp.Body)
			scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			eventID := ""
			eventData := ""

			for scanner.Scan() {
				line := scanner.Text()
				switch {
				case strings.HasPrefix(line, "id: "):
					eventID = line[4:]
				case strings.HasPrefix(line, "data: "):
					eventData = line[6:]
				case line == "" && eventData != "":
					if eventID != "" {
						lastID = eventID
					}
					var data map[string]any
					if err := json.Unmarshal([]byte(eventData), &data); err != nil {
						eventData, eventID = "", ""
						continue
					}
					if t, _ := data["type"].(string); t == "closed" || t == "expired" {
						resp.Body.Close()
						return
					}
					if enc, ok := data["enc"].(string); ok {
						iv, _ := data["iv"].(string)
						content, decErr := decryptWithKey(enc, iv, key)
						select {
						case ch <- WatchEvent{Content: content, Err: decErr}:
						case <-ctx.Done():
							resp.Body.Close()
							return
						}
					}
					eventData, eventID = "", ""
				}
			}
			resp.Body.Close()
		}
	}()

	return ch, nil
}

// ---------------------------------------------------------------------------
// Internal crypto
// ---------------------------------------------------------------------------

func decryptWithKey(encryptedHex, ivHex string, key []byte) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext hex: %w", err)
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return "", fmt.Errorf("invalid iv hex: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(plaintext), nil
}

// extractLegacyToken pulls the 64-char token out of a URL or returns the string as-is.
func extractLegacyToken(urlOrToken string) string {
	if strings.HasPrefix(urlOrToken, "http") {
		parts := strings.Split(strings.TrimSuffix(urlOrToken, "/"), "/")
		return parts[len(parts)-1]
	}
	return urlOrToken
}

func encrypt(plaintext, secret string) (encryptedHex, ivHex string, err error) {
	return encryptWithKey(plaintext, deriveKey(secret))
}

func encryptWithKey(plaintext string, key []byte) (encryptedHex, ivHex string, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(iv); err != nil {
		return "", "", err
	}
	ciphertext := gcm.Seal(nil, iv, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), hex.EncodeToString(iv), nil
}

// deriveKey is the sha256 derivation used by streams and KdfSHA256 notes.
func deriveKey(secret string) []byte {
	secretBytes, _ := hex.DecodeString(secret)
	hash := sha256.Sum256(secretBytes)
	return hash[:]
}

// noteKey derives a note's AES-256 key from its secret with the named kdf.
func noteKey(secret, kdf, password string) ([]byte, error) {
	if kdf != KdfPBKDF2 {
		return deriveKey(secret), nil
	}
	if password == "" {
		return nil, ErrPasswordRequired
	}
	salt, err := hex.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("voidnote: invalid secret: %w", err)
	}
	// Go strings are byte sequences, so the password goes in as the caller's (UTF-8) bytes.
	return pbkdf2.Key(sha256.New, password, salt, PBKDF2Iterations, 32)
}
