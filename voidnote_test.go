package voidnote

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Cross-client known answers shared with the iOS and Android suites
// (secret, iv and ciphertexts produced with WebCrypto).
const (
	katSecret = "00112233445566778899aabbccddeeff"
	katIV     = "a1b2c3d4e5f6000102030405"
	katSHA256 = "8f6ee0eb13334ea99cf53aa86bf4dc0fa4686b9c74f1bf98f3aa4bc216d70fc058ba9452266c57c681a5"
	katPBKDF2 = "3ca068b802bd8f8d25145619048f5de9b50ae3319ad9bc9f6af38bd9980107a311fb228dfd0b3e6b2c24"
	katUnicde = "c9aa7b0cd91b24f9c7982e6c0acb6233391307fc327b512c1ec87571aa62dbc5"
	testToken = "0123456789abcdef0123456789abcdef"
)

type recorded struct {
	path   string
	header http.Header
	body   []byte
}

type fakeServer struct {
	*httptest.Server
	mu    sync.Mutex
	calls []recorded
}

// newServer serves routes keyed by path suffix; each handler returns (status, headers, JSON body).
func newServer(t *testing.T, routes map[string]func(r recorded) (int, map[string]string, any)) *fakeServer {
	fs := &fakeServer{}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := recorded{path: r.URL.Path, header: r.Header.Clone(), body: body}
		fs.mu.Lock()
		fs.calls = append(fs.calls, rec)
		fs.mu.Unlock()
		for suffix, h := range routes {
			if strings.HasSuffix(r.URL.Path, suffix) {
				status, headers, out := h(rec)
				for k, v := range headers {
					w.Header().Set(k, v)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				json.NewEncoder(w).Encode(out)
				return
			}
		}
		t.Errorf("unexpected request %s", r.URL.Path)
		w.WriteHeader(500)
	}))
	t.Cleanup(fs.Close)
	return fs
}

func (fs *fakeServer) called(suffix string) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for _, c := range fs.calls {
		if strings.HasSuffix(c.path, suffix) {
			return true
		}
	}
	return false
}

func metaRoute(kdf string) func(recorded) (int, map[string]string, any) {
	return func(recorded) (int, map[string]string, any) {
		return 200, nil, map[string]any{"token": testToken, "exists": true, "type": "note", "viewLimit": 2, "viewsRemaining": 2, "kdf": kdf}
	}
}

func consumeRoute(kdf, encrypted string) func(recorded) (int, map[string]string, any) {
	return func(recorded) (int, map[string]string, any) {
		return 200, nil, map[string]any{"token": testToken, "encrypted": encrypted, "iv": katIV, "kdf": kdf, "consumed": true, "viewsRemaining": 1, "destroyed": false}
	}
}

func noteURL(base string) string { return base + "/n/" + testToken + "#" + katSecret }

// --- key derivation ---

func TestKnownAnswerKeys(t *testing.T) {
	cases := []struct{ kdf, password, want string }{
		{KdfSHA256, "", "a8faed6abbf35c12a4b26e40f6feb19d736d90045c83b9f9a31f638d323e6811"},
		{KdfPBKDF2, "correct horse battery staple", "7c0123695eb46911838d4c16fa259d7280c59060c6031130b8269b624faacd02"},
		{KdfPBKDF2, "pässwörd-日本", "2b547d9425d7d2a2dd01af3de73ec8d103c6a4f77c667f14ab406f92bbe88ac6"},
		{KdfPBKDF2, "pässwörd🔑", "bd9dc18065862b49fcb0b4f514fbc6021c5bc751313d261bd57ea9bd7dddbf10"},
	}
	for _, c := range cases {
		key, err := noteKey(katSecret, c.kdf, c.password)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(key); got != c.want {
			t.Errorf("%s %q: key %s, want %s", c.kdf, c.password, got, c.want)
		}
	}
}

// --- create ---

func createRoute(captured *map[string]any) func(recorded) (int, map[string]string, any) {
	return func(r recorded) (int, map[string]string, any) {
		json.Unmarshal(r.body, captured)
		return 201, nil, map[string]any{"token": testToken, "url": "https://voidnote.net/n/" + testToken, "expiresAt": "2026-10-15 12:00:00", "viewLimit": (*captured)["viewLimit"], "kdf": (*captured)["kdf"]}
	}
}

func openCreated(t *testing.T, body map[string]any, url, kdf, password string) string {
	t.Helper()
	secret := url[strings.Index(url, "#")+1:]
	key, err := noteKey(secret, kdf, password)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decryptWithKey(body["encrypted"].(string), body["iv"].(string), key)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func TestCreateAnonymousSendsNoAuthorization(t *testing.T) {
	var body map[string]any
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){"/api/v1/note/": createRoute(&body)})
	res, err := Create("hello", CreateOptions{Base: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if h := srv.calls[0].header.Get("Authorization"); h != "" {
		t.Fatalf("Authorization sent without a key: %q", h)
	}
	if body["expiresIn"] != float64(3600) || body["viewLimit"] != float64(1) || body["kdf"] != KdfSHA256 {
		t.Fatalf("body %v", body)
	}
	if res.Kdf != KdfSHA256 || res.ViewLimit != 1 {
		t.Fatalf("result %+v", res)
	}
	if got := openCreated(t, body, res.URL, KdfSHA256, ""); got != "hello" {
		t.Fatalf("decrypted %q", got)
	}
	// The secret in the URL is the one the server never saw
	if strings.Contains(string(srv.calls[0].body), res.URL[strings.Index(res.URL, "#")+1:]) {
		t.Fatal("secret sent to server")
	}
}

func TestCreateWithKeySendsBearer(t *testing.T) {
	var body map[string]any
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){"/api/v1/note/": createRoute(&body)})
	if _, err := Create("hello", CreateOptions{APIKey: "vn_test", Base: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if h := srv.calls[0].header.Get("Authorization"); h != "Bearer vn_test" {
		t.Fatalf("Authorization %q", h)
	}
}

func TestCreateWithPasswordUsesPBKDF2(t *testing.T) {
	var body map[string]any
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){"/api/v1/note/": createRoute(&body)})
	res, err := Create("guarded", CreateOptions{Password: "pässwörd-日本", MaxViews: 3, ExpiresIn: 2, Base: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if body["kdf"] != KdfPBKDF2 || body["viewLimit"] != float64(3) || body["expiresIn"] != float64(7200) {
		t.Fatalf("body %v", body)
	}
	if got := openCreated(t, body, res.URL, KdfPBKDF2, "pässwörd-日本"); got != "guarded" {
		t.Fatalf("decrypted %q", got)
	}
	// A pbkdf2 note never opens with the plain sha256 key
	secret := res.URL[strings.Index(res.URL, "#")+1:]
	sb, _ := hex.DecodeString(secret)
	plainKey := sha256.Sum256(sb)
	if _, err := decryptWithKey(body["encrypted"].(string), body["iv"].(string), plainKey[:]); err == nil {
		t.Fatal("pbkdf2 note opened with the sha256 key")
	}
}

func TestCreateSurfaces429RetryAfter(t *testing.T) {
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){
		"/api/v1/note/": func(recorded) (int, map[string]string, any) {
			return 429, map[string]string{"Retry-After": "60"}, map[string]string{"error": "Too many notes created. Try again shortly."}
		},
	})
	_, err := Create("x", CreateOptions{Base: srv.URL})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %T %v", err, err)
	}
	if apiErr.StatusCode != 429 || apiErr.RetryAfter != 60*time.Second || !strings.Contains(apiErr.Message, "Too many notes created") {
		t.Fatalf("%+v", apiErr)
	}
	if !strings.Contains(err.Error(), "retry after 1m0s") {
		t.Fatalf("message %q", err.Error())
	}
}

func TestCreateSurfaces400LimitMessage(t *testing.T) {
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){
		"/api/v1/note/": func(recorded) (int, map[string]string, any) {
			return 400, nil, map[string]string{"error": "viewLimit must be 1–10 without an account."}
		},
	})
	_, err := Create("x", CreateOptions{MaxViews: 50, Base: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "viewLimit must be 1–10 without an account.") {
		t.Fatalf("err %v", err)
	}
}

// --- read ---

func TestReadKnownAnswers(t *testing.T) {
	cases := []struct{ kdf, encrypted, password, want string }{
		{KdfSHA256, katSHA256, "", "voidnote-v1-sha256-kat ✓"},
		{KdfPBKDF2, katPBKDF2, "correct horse battery staple", "voidnote-v1-pbkdf2-kat ✓"},
		{KdfPBKDF2, katUnicde, "pässwörd-日本", "unicode password"},
	}
	for _, c := range cases {
		srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){
			"/meta/": metaRoute(c.kdf), "/consume/": consumeRoute(c.kdf, c.encrypted),
		})
		note, err := ReadWith(noteURL(srv.URL), ReadOptions{Password: c.password, Base: srv.URL})
		if err != nil {
			t.Fatalf("%s: %v", c.want, err)
		}
		if note.Content != c.want || note.Kdf != c.kdf || note.MaxViews != 2 || note.ViewCount != 1 || note.ViewsRemaining != 1 {
			t.Fatalf("%+v", note)
		}
	}
}

func TestReadPasswordNoteWithoutPasswordFailsBeforeConsume(t *testing.T) {
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){
		"/meta/": metaRoute(KdfPBKDF2), "/consume/": consumeRoute(KdfPBKDF2, katPBKDF2),
	})
	_, err := ReadFrom(noteURL(srv.URL), srv.URL)
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("err %v", err)
	}
	if srv.called("/consume/") {
		t.Fatal("consume called")
	}
}

func TestReadWrongPassword(t *testing.T) {
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){
		"/meta/": metaRoute(KdfPBKDF2), "/consume/": consumeRoute(KdfPBKDF2, katPBKDF2),
	})
	_, err := ReadWith(noteURL(srv.URL), ReadOptions{Password: "wrong", Base: srv.URL})
	if !errors.Is(err, ErrDecryption) {
		t.Fatalf("err %v", err)
	}
}

func TestReadUnknownKdfFailsBeforeConsume(t *testing.T) {
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){
		"/meta/": metaRoute("argon2id"), "/consume/": consumeRoute("argon2id", katSHA256),
	})
	_, err := ReadWith(noteURL(srv.URL), ReadOptions{Password: "x", Base: srv.URL})
	if !errors.Is(err, ErrUnsupportedKdf) {
		t.Fatalf("err %v", err)
	}
	if srv.called("/consume/") {
		t.Fatal("consume called")
	}
}

func TestReadMissingNote(t *testing.T) {
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){
		"/meta/": func(recorded) (int, map[string]string, any) {
			return 200, nil, map[string]any{"token": testToken, "exists": false}
		},
	})
	if _, err := ReadFrom(noteURL(srv.URL), srv.URL); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v", err)
	}
}

func TestReadSurfaces410(t *testing.T) {
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){
		"/meta/": metaRoute(KdfSHA256),
		"/consume/": func(recorded) (int, map[string]string, any) {
			return 410, nil, map[string]string{"error": "Note not found or already destroyed."}
		},
	})
	_, err := ReadFrom(noteURL(srv.URL), srv.URL)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 410 || !strings.Contains(apiErr.Message, "already destroyed") {
		t.Fatalf("err %v", err)
	}
}

// --- peek ---

func TestPeekExposesKdf(t *testing.T) {
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){"/meta/": metaRoute(KdfPBKDF2)})
	m, err := Peek(noteURL(srv.URL), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m.Kdf != KdfPBKDF2 || m.ViewsRemaining != 2 {
		t.Fatalf("%+v", m)
	}
}

func TestPeekSurfacesErrors(t *testing.T) {
	srv := newServer(t, map[string]func(recorded) (int, map[string]string, any){
		"/meta/": func(recorded) (int, map[string]string, any) {
			return 429, nil, map[string]string{"error": "Too many requests."}
		},
	})
	if _, err := Peek(noteURL(srv.URL), srv.URL); err == nil || !strings.Contains(err.Error(), "Too many requests.") {
		t.Fatalf("err %v", err)
	}
}
