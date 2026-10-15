# voidnote-go

Official Go SDK for [VoidNote](https://voidnote.net): zero-knowledge self-destructing notes and live encrypted streams.

**v0.5.0** · Go 1.24+ · stdlib only, zero external dependencies · no account needed for notes

## Install

```bash
go get github.com/quantum-encoding/voidnote-go
```

## Quick start

```go
package main

import (
    "fmt"
    voidnote "github.com/quantum-encoding/voidnote-go"
)

func main() {
    // No account or API key needed. Content is encrypted locally; the server never sees it.
    note, err := voidnote.Create("my secret value", voidnote.CreateOptions{})
    if err != nil {
        panic(err)
    }
    fmt.Println(note.URL)    // https://voidnote.net/n/<tokenId>#<secret>

    opened, err := voidnote.Read(note.URL)
    if err != nil {
        panic(err)
    }
    fmt.Println(opened.Content)
}
```

## API

### `Create(content string, opts CreateOptions) (*CreateResult, error)`

Encrypt content locally and store the ciphertext. `ExpiresIn` is in hours.

```go
result, err := voidnote.Create("deploy key: abc123", voidnote.CreateOptions{
    MaxViews:  3,  // default 1
    ExpiresIn: 6,  // hours, default 1
})
fmt.Println(result.URL)        // full shareable URL, includes #secret
fmt.Println(result.Token)      // 32-char tokenId only
fmt.Println(result.ExpiresAt, result.ViewLimit, result.Kdf)
```

Without an `APIKey` the note is anonymous: up to 168 hours (7 days) and 10 views, rate-limited per IP. An API key from a free account raises that to 720 hours and 100 views:

```go
voidnote.Create("deploy key: abc123", voidnote.CreateOptions{APIKey: "vn_...", MaxViews: 50, ExpiresIn: 720})
```

Add a `Password` and the reader needs it as well as the link. The key is then PBKDF2-HMAC-SHA256 (600,000 iterations) of the password, salted with the link's secret:

```go
guarded, err := voidnote.Create("db password: hunter2", voidnote.CreateOptions{Password: "correct horse"})
// share guarded.URL and the password through different channels
```

### `Read(url) / ReadWith(url, ReadOptions) (*ReadResult, error)`

Fetch and decrypt a note. Consumes one view. Accepts v1 URLs (`/n/<token>#<secret>`) and legacy URLs.

```go
note, err := voidnote.Read("https://voidnote.net/n/<tokenId>#<secret>")
if err != nil {
    panic(err)
}
fmt.Println(note.Content)         // decrypted plaintext
fmt.Println(note.ViewsRemaining)  // views left after this read
fmt.Println(note.Destroyed)       // true if this was the last view

// A note created with a password
guarded, err := voidnote.ReadWith(url, voidnote.ReadOptions{Password: "correct horse"})
```

Before using a view, `Read` checks the note's metadata. A missing note (`ErrNotFound`), a password note read without a password (`ErrPasswordRequired`) or an unknown key derivation (`ErrUnsupportedKdf`) returns without touching the view. A wrong password (`ErrDecryption`) can only be detected after decrypting, so it does use the view.

### `Peek(urlOrToken string) (*PeekResult, error)`

Check metadata without consuming a view. `Kdf` is `voidnote.KdfPBKDF2` when the note needs a password.

```go
meta, err := voidnote.Peek("https://voidnote.net/n/<tokenId>#<secret>")
fmt.Println(meta.Exists, meta.ViewsRemaining, meta.ExpiresAt, meta.Kdf)
```

### Errors

Server refusals are `*voidnote.APIError` with the status, the server's message and, on 429, `RetryAfter`. The sentinel errors above work with `errors.Is`.

```go
_, err := voidnote.Create("x", voidnote.CreateOptions{})
var apiErr *voidnote.APIError
if errors.As(err, &apiErr) && apiErr.StatusCode == 429 {
    fmt.Printf("rate limited, retry in %s: %s\n", apiErr.RetryAfter, apiErr.Message)
}
```

### Void Streams

Live encrypted real-time channels. Creating one needs an API key from a free account; watching doesn't.

```go
import (
    "context"
    "fmt"
    voidnote "github.com/quantum-encoding/voidnote-go"
)

// Create a channel
stream, err := voidnote.CreateStream(voidnote.StreamOptions{
    APIKey: "vn_...",
    Title:  "Deploy #42",
})
fmt.Println(stream.URL)  // share this URL with watchers

// Write messages (Write and Close are authenticated with the same API key)
stream.Write("Starting deployment...")
stream.Write("Build complete.")
stream.Close()  // self-destructs all content

// Watch a stream: channel of decrypted messages
ctx := context.Background()
events, _ := voidnote.Watch(ctx, "https://voidnote.net/stream/<token>")
for event := range events {
    if event.Err != nil {
        fmt.Println("error:", event.Err)
        continue
    }
    fmt.Println(event.Content)
}

// Keep writing to a stream you created earlier (e.g. in another process)
resumed := voidnote.ResumeStreamWithKey("https://voidnote.net/stream/<token>", "vn_...")
resumed.Write("Deploy finished.")

// Password-protected stream
events, _ = voidnote.WatchWith(ctx, "https://voidnote.net/stream/<token>",
    voidnote.WatchOptions{Password: "hunter2"})
```

## Security model

```
server generates  tokenId  (32-char hex, stored as lookup key)
client generates  secret   (32-char hex, NEVER sent to server)

key        = SHA-256(hex_decode(secret))                                  kdf "sha256"
key        = PBKDF2-HMAC-SHA256(password, hex_decode(secret), 600000)     kdf "pbkdf2-sha256-600k"
ciphertext = AES-256-GCM(plaintext, key, random_12_byte_iv)
share URL  = https://voidnote.net/n/{tokenId}#{secret}
```

The `#fragment` is never transmitted to HTTP servers per spec. The server has ciphertext; you have the key.

## Requirements

- Go 1.24+ (for `crypto/pbkdf2`)
- No external dependencies (stdlib only)

## Tests

```bash
go test ./...                              # mocked network
go test -tags live -run TestLive -v .      # creates real anonymous notes on voidnote.net
```

## Links

- [voidnote.net](https://voidnote.net)
- [API reference](https://voidnote.net/docs)
- [CLI reference](https://voidnote.net/cli)
- [GitHub](https://github.com/quantum-encoding/voidnote-go)
