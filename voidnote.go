// Package voidnote is the official Go SDK for VoidNote.
//
// Zero-knowledge self-destructing notes. The key lives in the link. We never see it.
//
// Usage:
//
//	result, err := voidnote.Read("https://voidnote.net/note/abc123...")
//	result, err := voidnote.Create("my secret", voidnote.CreateOptions{APIKey: "vn_..."})
package voidnote

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultBase = "https://voidnote.net"

// ReadResult holds the decrypted content of a note.
type ReadResult struct {
	Content   string
	Title     string
	ViewCount int
	MaxViews  int
	Destroyed bool // true if view limit was reached after this read
}

// CreateOptions configures how a new note is created.
type CreateOptions struct {
	APIKey   string // required: vn_... from your dashboard
	Title    string // optional
	MaxViews int    // 1–100, defaults to 1
	Base     string // optional: override API base URL
}

// CreateResult holds the shareable link for a newly created note.
type CreateResult struct {
	URL       string
	ExpiresAt string
}

// Read fetches and decrypts a VoidNote.
// urlOrToken may be a full URL (https://voidnote.net/note/<token>) or just the 64-char token.
func Read(urlOrToken string) (*ReadResult, error) {
	return ReadFrom(urlOrToken, "")
}

// ReadFrom is like Read but allows overriding the base URL.
func ReadFrom(urlOrToken, base string) (*ReadResult, error) {
	if base == "" {
		base = defaultBase
	}

	token := extractToken(urlOrToken)
	if len(token) != 64 {
		return nil, fmt.Errorf("voidnote: invalid token length %d (want 64)", len(token))
	}

	tokenID := token[:32]
	secret := token[32:]

	resp, err := http.Get(base + "/api/note/" + tokenID)
	if err != nil {
		return nil, fmt.Errorf("voidnote: fetch failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("voidnote: reading response: %w", err)
	}

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("voidnote: note not found or already destroyed")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("voidnote: server returned %d: %s", resp.StatusCode, string(body))
	}

	var payload struct {
		EncryptedContent string `json:"encrypted_content"`
		IV               string `json:"iv"`
		Title            string `json:"title"`
		ViewCount        int    `json:"view_count"`
		MaxViews         int    `json:"max_views"`
		Destroyed        bool   `json:"destroyed"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("voidnote: parsing response: %w", err)
	}

	content, err := decrypt(payload.EncryptedContent, payload.IV, secret)
	if err != nil {
		return nil, fmt.Errorf("voidnote: decryption failed: %w", err)
	}

	return &ReadResult{
		Content:   content,
		Title:     payload.Title,
		ViewCount: payload.ViewCount,
		MaxViews:  payload.MaxViews,
		Destroyed: payload.Destroyed,
	}, nil
}

// Create encrypts content client-side and stores a new note on VoidNote.
func Create(content string, opts CreateOptions) (*CreateResult, error) {
	if opts.APIKey == "" {
		return nil, fmt.Errorf("voidnote: APIKey is required")
	}
	if opts.MaxViews == 0 {
		opts.MaxViews = 1
	}
	if opts.Base == "" {
		opts.Base = defaultBase
	}

	// Generate 32 random bytes → 64 hex char token
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("voidnote: generating token: %w", err)
	}
	fullToken := hex.EncodeToString(raw)
	tokenID := fullToken[:32]
	secret := fullToken[32:]

	encryptedContent, iv, err := encrypt(content, secret)
	if err != nil {
		return nil, fmt.Errorf("voidnote: encryption failed: %w", err)
	}

	reqBody, _ := json.Marshal(map[string]interface{}{
		"tokenId":          tokenID,
		"encryptedContent": encryptedContent,
		"iv":               iv,
		"maxViews":         opts.MaxViews,
		"title":            opts.Title,
	})

	req, err := http.NewRequest("POST", opts.Base+"/api/notes", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("voidnote: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+opts.APIKey)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("voidnote: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("voidnote: reading response: %w", err)
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, fmt.Errorf("voidnote: server returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ExpiresAt string `json:"expires_at"`
	}
	json.Unmarshal(body, &result)

	return &CreateResult{
		URL:       opts.Base + "/note/" + fullToken,
		ExpiresAt: result.ExpiresAt,
	}, nil
}

// ---------------------------------------------------------------------------
// Void Stream — live encrypted real-time channels
// ---------------------------------------------------------------------------

// StreamOptions configures a new Void Stream.
type StreamOptions struct {
	APIKey string // required: vn_... from your dashboard
	Title  string // optional
	TTL    int    // 3600 (1h), 21600 (6h), or 86400 (24h) — defaults to 3600
	Base   string // optional: override API base URL
}

// StreamHandle is a live Void Stream. Write encrypted messages and close to self-destruct.
// Returned by CreateStream.
//
// Example:
//
//	stream, _ := voidnote.CreateStream(voidnote.StreamOptions{APIKey: "vn_..."})
//	fmt.Println(stream.URL)  // share this with viewers
//	stream.Write("Deployment starting…")
//	stream.Write("Done — 47/47 passed")
//	stream.Close()
type StreamHandle struct {
	URL       string
	ExpiresAt string
	fullToken string
	secret    string
	base      string
}

// WatchEvent is a single decrypted message received from a stream.
type WatchEvent struct {
	Content string
	Err     error
}

// CreateStream creates a new Void Stream. Costs 1 credit.
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

	reqBody, _ := json.Marshal(map[string]interface{}{
		"tokenId": tokenID,
		"title":   opts.Title,
		"ttl":     opts.TTL,
	})
	req, _ := http.NewRequest("POST", opts.Base+"/api/stream", bytes.NewReader(reqBody))
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
		return nil, fmt.Errorf("voidnote: server returned %d: %s", resp.StatusCode, string(body))
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
	}, nil
}

// Write encrypts content client-side and pushes it to the stream.
// The server never sees the plaintext.
func (s *StreamHandle) Write(content string) error {
	encryptedContent, iv, err := encrypt(content, s.secret)
	if err != nil {
		return fmt.Errorf("voidnote: encryption failed: %w", err)
	}
	body, _ := json.Marshal(map[string]string{
		"encryptedContent": encryptedContent,
		"iv":               iv,
	})
	req, _ := http.NewRequest("POST", s.base+"/api/stream/"+s.fullToken+"/write", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("voidnote: write failed: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("voidnote: write returned %d", resp.StatusCode)
	}
	return nil
}

// Close marks the stream as closed. Viewers receive a closed event and all
// content self-destructs.
func (s *StreamHandle) Close() error {
	req, _ := http.NewRequest("POST", s.base+"/api/stream/"+s.fullToken+"/close", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("voidnote: close failed: %w", err)
	}
	resp.Body.Close()
	return nil
}

// ResumeStream reconstructs a StreamHandle from a full 64-char token or URL.
// Use this when you have the stream URL but didn't create the stream in this process
// (e.g. from the CLI, or when resuming after a restart).
// The handle can Write, Close, and be passed to Watch.
func ResumeStream(urlOrToken string, base ...string) *StreamHandle {
	apiBase := defaultBase
	if len(base) > 0 && base[0] != "" {
		apiBase = base[0]
	}
	token := extractToken(urlOrToken)
	return &StreamHandle{
		URL:       apiBase + "/stream/" + token,
		fullToken: token,
		secret:    token[32:],
		base:      apiBase,
	}
}

// Watch subscribes to a Void Stream and returns a channel of decrypted messages.
// The returned channel is closed when the stream ends or ctx is cancelled.
// Automatically reconnects using SSE Last-Event-ID.
//
// Example:
//
//	events, _ := voidnote.Watch(ctx, "https://voidnote.net/stream/abc123...")
//	for event := range events {
//	    if event.Err != nil { log.Fatal(event.Err) }
//	    fmt.Println(event.Content)
//	}
func Watch(ctx context.Context, urlOrToken string, base ...string) (<-chan WatchEvent, error) {
	apiBase := defaultBase
	if len(base) > 0 && base[0] != "" {
		apiBase = base[0]
	}

	token := extractToken(urlOrToken)
	if len(token) != 64 {
		return nil, fmt.Errorf("voidnote: invalid token length %d (want 64)", len(token))
	}
	secret := token[32:]
	key := deriveKey(secret)

	ch := make(chan WatchEvent, 32)

	go func() {
		defer close(ch)
		lastID := ""

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			req, err := http.NewRequestWithContext(ctx, "GET", apiBase+"/api/stream/"+token+"/events", nil)
			if err != nil {
				return
			}
			if lastID != "" {
				req.Header.Set("Last-Event-ID", lastID)
			}

			// No timeout — SSE connections are long-lived
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					time.Sleep(2 * time.Second)
					continue
				}
			}

			scanner := bufio.NewScanner(resp.Body)
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

					var data map[string]interface{}
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
			// Segment ended — reconnect
		}
	}()

	return ch, nil
}

// decryptWithKey decrypts using a pre-derived AES key (as []byte).
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

// extractToken pulls the 64-char token out of a full URL or returns the string as-is.
func extractToken(urlOrToken string) string {
	if strings.HasPrefix(urlOrToken, "http") {
		parts := strings.Split(strings.TrimSuffix(urlOrToken, "/"), "/")
		return parts[len(parts)-1]
	}
	return urlOrToken
}

// encrypt performs AES-256-GCM encryption using SHA-256(secret) as the key.
func encrypt(plaintext, secret string) (encryptedHex, ivHex string, err error) {
	key := deriveKey(secret)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	iv := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err = rand.Read(iv); err != nil {
		return "", "", err
	}

	ciphertext := gcm.Seal(nil, iv, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), hex.EncodeToString(iv), nil
}

// decrypt reverses AES-256-GCM encryption.
func decrypt(encryptedHex, ivHex, secret string) (string, error) {
	key := deriveKey(secret)

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
		return "", fmt.Errorf("decryption failed (wrong key or tampered data): %w", err)
	}
	return string(plaintext), nil
}

// deriveKey returns SHA-256(secret) as the AES key.
func deriveKey(secret string) []byte {
	secretBytes, _ := hex.DecodeString(secret)
	hash := sha256.Sum256(secretBytes)
	return hash[:]
}
