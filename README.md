# voidnote-go

Official Go SDK for [VoidNote](https://voidnote.net) — zero-knowledge self-destructing notes.

## Install

```bash
go get github.com/quantum-encoding/voidnote-go
```

## Usage

### Read a note

```go
package main

import (
    "fmt"
    voidnote "github.com/quantum-encoding/voidnote-go"
)

func main() {
    result, err := voidnote.Read("https://voidnote.net/note/abc123...")
    if err != nil {
        panic(err)
    }
    fmt.Println(result.Content)   // decrypted content
    fmt.Println(result.Destroyed) // true if view limit was reached
}
```

### Create a note (requires API key)

```go
result, err := voidnote.Create("my secret value", voidnote.CreateOptions{
    APIKey:   "vn_...",
    MaxViews: 1,
    Title:    "Deploy key",
})
if err != nil {
    panic(err)
}
fmt.Println(result.URL) // share this link
```

## Requirements

- Go 1.21+
- No external dependencies (stdlib only)

## Links

- [voidnote.net](https://voidnote.net)
- [How it works](https://voidnote.net/how-it-works)
- [GitHub](https://github.com/quantum-encoding/voidnote-go)
