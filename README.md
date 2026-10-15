# voidnote-go

Official Go SDK for [VoidNote](https://voidnote.net) — zero-knowledge self-destructing notes and live encrypted streams.

**v0.4.0** · Go 1.21+ · stdlib only, zero external dependencies · zero-knowledge v1 API

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
    // Create a note — content is encrypted locally, server never sees plaintext
    result, err := voidnote.Create("my secret value", voidnote.CreateOptions{
        APIKey:    "vn_...",
        MaxViews:  1,   // destroy after this many reads (1–100)
        ExpiresIn: 1,   // hours until expiry (1–720)
    })
    if err != nil {
        panic(err)
    }
    fmt.Println(result.URL)    // https://voidnote.net/n/<tokenId>#<secret>
    fmt.Println(result.Token)  // 32-char tokenId
}
```

## API

### `Create(content string, opts CreateOptions) (*CreateResult, error)`

Encrypt content locally and store the ciphertext. Requires an API key from your [dashboard](https://voidnote.net/dashboard).

```go
result, err := voidnote.Create("deploy key: abc123", voidnote.CreateOptions{
    APIKey:    "vn_...",
    MaxViews:  3,
    ExpiresIn: 6,  // 6 hours
})
fmt.Println(result.URL)        // full shareable URL — includes #secret
fmt.Println(result.Token)      // 32-char tokenId only
fmt.Println(result.ExpiresAt)
```

### `Read(urlOrToken string) (*ReadResult, error)`

Fetch and decrypt a note. Consumes one view. Accepts both v1 URLs (`/n/<token>#<secret>`) and legacy URLs.

```go
note, err := voidnote.Read("https://voidnote.net/n/<tokenId>#<secret>")
if err != nil {
    panic(err)
}
fmt.Println(note.Content)         // decrypted plaintext
fmt.Println(note.ViewsRemaining)  // views left after this read
fmt.Println(note.Destroyed)       // true if this was the last view
```

### `Peek(urlOrToken string) (*PeekResult, error)`

Check metadata without consuming a view.

```go
meta, err := voidnote.Peek("https://voidnote.net/n/<tokenId>#<secret>")
fmt.Println(meta.Exists)
fmt.Println(meta.ViewsRemaining)
fmt.Println(meta.ExpiresAt)
```

### Void Streams

Live encrypted real-time channels. Messages are encrypted before leaving your machine.

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

// Watch a stream — channel of decrypted messages
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

### Crypto payments

```go
// Create a payment order
order, err := voidnote.CreateCryptoOrder(voidnote.CryptoOrderOptions{
    APIKey:   "vn_...",
    BundleID: "starter",  // "test" | "starter" | "standard" | "pro"
    Chain:    "polygon",
    Token:    "USDT",
})
fmt.Printf("Send %s %s to %s\n", order.Amount, order.Token, order.ToAddress)

// After sending, submit the tx hash
result, err := voidnote.SubmitCryptoPayment(voidnote.SubmitPaymentOptions{
    APIKey:  "vn_...",
    OrderID: order.OrderID,
    TxHash:  "0x...",
})
fmt.Printf("+%d credits\n", result.CreditsAdded)
```

## Security model

```
server generates  tokenId  (32-char hex — stored as lookup key)
client generates  secret   (32-char hex — NEVER sent to server)

key        = SHA-256(hex_decode(secret))
ciphertext = AES-256-GCM(plaintext, key, random_12_byte_iv)
share URL  = https://voidnote.net/n/{tokenId}#{secret}
```

The `#fragment` is never transmitted to HTTP servers per spec. The server has ciphertext; you have the key.

## Requirements

- Go 1.21+
- No external dependencies (stdlib only)

## Links

- [voidnote.net](https://voidnote.net)
- [API reference](https://voidnote.net/docs)
- [CLI reference](https://voidnote.net/cli)
- [GitHub](https://github.com/quantum-encoding/voidnote-go)
