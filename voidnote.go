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
	"bytes"
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
