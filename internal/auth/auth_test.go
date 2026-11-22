package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(body string, status int) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Header: make(http.Header)}
}
func marshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type fixture struct {
	private ed25519.PrivateKey
	jwk     map[string]any
	kid     string
}

func signing(t *testing.T, kid string) fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{priv, map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub), "alg": "EdDSA", "use": "sig"}, kid}
}
func (f fixture) token(t *testing.T, overrides map[string]any, headers map[string]any) string {
	t.Helper()
	claims := map[string]any{"iss": "danysik-auth", "aud": "banwords", "sub": "123", "iat": 1000, "exp": 1100, "perms": []string{"banwords:dictionaries:read"}}
	for k, v := range overrides {
		claims[k] = v
	}
	header := map[string]any{"alg": "EdDSA", "kid": f.kid, "typ": "JWT"}
	for k, v := range headers {
		if text, ok := v.(string); ok && text == missing {
			delete(header, k)
		} else {
			header[k] = v
		}
	}
	return f.raw(marshal(t, header), marshal(t, claims))
}
func (f fixture) raw(header, claims []byte) string {
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.private, []byte(unsigned)))
}

const missing = "<absent-test-field>"

func testVerifier(t *testing.T, f fixture, modify func(*Options)) *Verifier {
	t.Helper()
	body := string(marshal(t, map[string]any{"keys": []any{f.jwk}}))
	opts := Options{URL: "http://auth.invalid/keys", Now: func() time.Time { return time.Unix(1000, 0) }, Client: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Auth-Token") != "" {
			return nil, errors.New("unexpected request")
		}
		return response(body, 200), nil
	})}}
	if modify != nil {
		modify(&opts)
	}
	return New(opts)
}
func rejected(t *testing.T, v *Verifier, token string, want error) {
	t.Helper()
	_, err := v.Verify(context.Background(), token)
	if !errors.Is(err, want) {
		t.Fatalf("Verify error %v; want %v", err, want)
	}
}

func TestValidTokensAndExactClaims(t *testing.T) {
	f := signing(t, "first")
	v := testVerifier(t, f, nil)
	for _, overrides := range []map[string]any{nil, {"perms": []string{"superadmin"}}, {"nbf": 1000}, {"sub": strings.Repeat("𐐀", 64), "perms": []string{"banwords:dictionaries:read", strings.Repeat("𐐀", 64)}}, {"iat": 1005}} {
		got, err := v.Verify(context.Background(), f.token(t, overrides, nil))
		if err != nil {
			t.Fatal(err)
		}
		if got.Subject == "" || got.Issuer != "danysik-auth" || got.Audience != "banwords" || got.ExpiresAt != 1100 {
			t.Fatalf("wrong claims %#v", got)
		}
	}
	if _, err := v.Verify(context.Background(), f.token(t, nil, map[string]any{"typ": missing})); err != nil {
		t.Fatal(err)
	}
	// JS Number.isSafeInteger also accepts an integral JSON exponent.
	raw := `{"iss":"danysik-auth","aud":"banwords","sub":"123","exp":1.1e3,"perms":["banwords:dictionaries:read"]}`
	if _, err := v.Verify(context.Background(), f.raw(marshal(t, map[string]any{"alg": "EdDSA", "kid": f.kid}), []byte(raw))); err != nil {
		t.Fatal(err)
	}
	invalid := []map[string]any{{"iss": "other"}, {"iss": nil}, {"aud": "other-service"}, {"aud": []string{"banwords"}}, {"sub": ""}, {"sub": nil}, {"sub": strings.Repeat("a", 129)}, {"sub": strings.Repeat("𐐀", 65)}, {"exp": nil}, {"exp": 1000}, {"exp": 999}, {"exp": "1100"}, {"exp": 1100.1}, {"exp": 9007199254740992.0}, {"nbf": 1001}, {"nbf": "1000"}, {"nbf": nil}, {"iat": 1006}, {"iat": "1000"}, {"iat": false}, {"perms": nil}, {"perms": []string{}}, {"perms": []string{"banwords"}}, {"perms": []string{"banwords:dictionaries"}}, {"perms": []any{"banwords:dictionaries:read", nil}}, {"perms": []string{"banwords:dictionaries:read", strings.Repeat("a", 129)}}, {"perms": append([]string{"banwords:dictionaries:read"}, make([]string, 128)...)}}
	for i, overrides := range invalid {
		t.Run(fmt.Sprintf("case_%02d", i), func(t *testing.T) { rejected(t, v, f.token(t, overrides, nil), ErrInvalidToken) })
	}
	// Field names are case-sensitive as they are in JSON.parse, unlike direct Go
	// struct decoding. An uppercase alias must never satisfy a required claim.
	for _, payload := range []string{`{"ISS":"danysik-auth","aud":"banwords","sub":"123","exp":1100,"perms":["superadmin"]}`, `{"iss":"danysik-auth","aud":"banwords","sub":"123","EXP":1100,"perms":["superadmin"]}`, `{"iss":"danysik-auth","aud":"banwords","sub":"123","exp":1100,"perms":{}}`, `{"iss":"danysik-auth","aud":"banwords","sub":"123","perms":["superadmin"]}`} {
		rejected(t, v, f.raw(marshal(t, map[string]any{"alg": "EdDSA", "kid": f.kid}), []byte(payload)), ErrInvalidToken)
	}
}

func TestMalformedTokensAndHeaders(t *testing.T) {
	f := signing(t, "kid")
	var fetches atomic.Int64
	v := testVerifier(t, f, func(o *Options) {
		o.Client = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			fetches.Add(1)
			return response(string(marshal(t, map[string]any{"keys": []any{f.jwk}})), 200), nil
		})}
	})
	for _, raw := range []string{"", strings.Repeat("a", 8193), "a.b", "a.b.c.d", "a=.b.c", "..", "YQ.YQ.YQ", "e30.bm90LWpzb24.YQ"} {
		rejected(t, v, raw, ErrInvalidToken)
	}
	for _, overrides := range []map[string]any{{"alg": "none"}, {"alg": "HS256"}, {"alg": nil}, {"kid": missing}, {"kid": ""}, {"kid": 1}, {"kid": strings.Repeat("x", 129)}, {"kid": strings.Repeat("𐐀", 65)}, {"typ": "other"}, {"typ": nil}} {
		rejected(t, v, f.token(t, nil, overrides), ErrInvalidToken)
	}
	for _, header := range []string{"null", "[]", "\"text\"", `{"ALG":"EdDSA","kid":"kid"}`} {
		rejected(t, v, f.raw([]byte(header), []byte("{}")), ErrInvalidToken)
	}
	for _, claims := range []string{"null", "[]", "\"text\"", "{"} {
		rejected(t, v, f.raw(marshal(t, map[string]any{"alg": "EdDSA", "kid": f.kid}), []byte(claims)), ErrInvalidToken)
	}
	if fetches.Load() != 0 {
		t.Fatalf("malformed tokens fetched keys %d times", fetches.Load())
	}
	wrong := signing(t, "other")
	rejected(t, v, wrong.token(t, nil, nil), ErrInvalidToken)
	raw := f.token(t, nil, nil)
	parts := strings.Split(raw, ".")
	rejected(t, v, parts[0]+"."+parts[1]+".YQ", ErrInvalidToken)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"hacked"}`))
	rejected(t, v, strings.Join(parts, "."), ErrInvalidToken)
	for _, raw := range []string{"YQ=", "YQ\n", "YR", "YQ ", "!"} {
		if _, ok := decodeBase64(raw); ok {
			t.Fatalf("accepted malformed base64 %q", raw)
		}
	}
}

func TestCacheRotationCooldownAndCoalescing(t *testing.T) {
	first, second := signing(t, "first"), signing(t, "second")
	var clock atomic.Int64
	clock.Store(1000)
	var fetches atomic.Int64
	var keysMu sync.Mutex
	keys := []any{first.jwk}
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	v := testVerifier(t, first, func(o *Options) {
		o.Now = func() time.Time { return time.Unix(clock.Load(), 0) }
		o.Client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			fetches.Add(1)
			if fetches.Load() == 1 {
				started <- struct{}{}
				select {
				case <-gate:
				case <-r.Context().Done():
					return nil, r.Context().Err()
				}
			}
			keysMu.Lock()
			raw := marshal(t, map[string]any{"keys": keys})
			keysMu.Unlock()
			return response(string(raw), 200), nil
		})}
	})
	const count = 20
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Go(func() { _, err := v.Verify(context.Background(), first.token(t, nil, nil)); errs <- err })
	}
	<-started
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("coalesced requests=%d", fetches.Load())
	}
	if _, err := v.Verify(context.Background(), first.token(t, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 1 {
		t.Fatal("fresh cache was not reused")
	}
	keysMu.Lock()
	keys = []any{first.jwk, second.jwk}
	keysMu.Unlock()
	clock.Store(1001)
	rejected(t, v, second.token(t, nil, nil), ErrInvalidToken)
	if fetches.Load() != 1 {
		t.Fatal("kid refresh bypassed cooldown")
	}
	clock.Store(1005)
	if _, err := v.Verify(context.Background(), second.token(t, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 2 {
		t.Fatal("rotated key was not fetched")
	}
	keysMu.Lock()
	keys = []any{second.jwk}
	keysMu.Unlock()
	clock.Store(1305)
	if _, err := v.Verify(context.Background(), second.token(t, map[string]any{"iat": 1305, "exp": 1405}, nil)); err != nil {
		t.Fatal(err)
	}
	rejected(t, v, first.token(t, map[string]any{"iat": 1305, "exp": 1405}, nil), ErrInvalidToken)
	if fetches.Load() != 3 {
		t.Fatalf("TTL refresh count=%d", fetches.Load())
	}
}

func TestOutageExpiredCacheAndRecovery(t *testing.T) {
	f := signing(t, "kid")
	var clock atomic.Int64
	clock.Store(1000)
	var failed atomic.Bool
	var fetches atomic.Int64
	v := testVerifier(t, f, func(o *Options) {
		o.Now = func() time.Time { return time.Unix(clock.Load(), 0) }
		o.Client = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			fetches.Add(1)
			if failed.Load() {
				return nil, errors.New("upstream contains secret")
			}
			return response(string(marshal(t, map[string]any{"keys": []any{f.jwk}})), 200), nil
		})}
	})
	if _, err := v.Verify(context.Background(), f.token(t, nil, nil)); err != nil {
		t.Fatal(err)
	}
	failed.Store(true)
	clock.Store(1300)
	for i := 0; i < 2; i++ {
		rejected(t, v, f.token(t, map[string]any{"iat": 1300, "exp": 1400}, nil), ErrJWKSUnavailable)
	}
	if fetches.Load() != 2 {
		t.Fatal("outage cooldown was not enforced")
	}
	failed.Store(false)
	clock.Store(1305)
	if _, err := v.Verify(context.Background(), f.token(t, map[string]any{"iat": 1305, "exp": 1400}, nil)); err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 3 {
		t.Fatal("outage recovery did not refresh")
	}
}

func TestTimeoutAndWaiterCancellation(t *testing.T) {
	f := signing(t, "kid")
	var now atomic.Int64
	now.Store(1000)
	var hung atomic.Bool
	hung.Store(true)
	var aborted atomic.Bool
	v := testVerifier(t, f, func(o *Options) {
		o.Timeout = 10 * time.Millisecond
		o.Now = func() time.Time { return time.Unix(now.Load(), 0) }
		o.Client = &http.Client{Timeout: time.Hour, Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			if hung.Load() {
				<-r.Context().Done()
				aborted.Store(true)
				return nil, r.Context().Err()
			}
			return response(string(marshal(t, map[string]any{"keys": []any{f.jwk}})), 200), nil
		})}
	})
	rejected(t, v, f.token(t, nil, nil), ErrJWKSUnavailable)
	if !aborted.Load() {
		t.Fatal("timeout did not cancel upstream")
	}
	now.Store(1005)
	hung.Store(false)
	if _, err := v.Verify(context.Background(), f.token(t, nil, nil)); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var fetches atomic.Int64
	shared := testVerifier(t, f, func(o *Options) {
		o.Client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			fetches.Add(1)
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
			return response(string(marshal(t, map[string]any{"keys": []any{f.jwk}})), 200), nil
		})}
	})
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := shared.Verify(ctx, f.token(t, nil, nil)); first <- err }()
	<-started
	cancel()
	if !errors.Is(<-first, context.Canceled) {
		t.Fatal("cancelled waiter was not released")
	}
	second := make(chan error, 1)
	go func() { _, err := shared.Verify(context.Background(), f.token(t, nil, nil)); second <- err }()
	close(release)
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 1 {
		t.Fatal("cancelled waiter poisoned shared refresh")
	}
}

func TestMalformedJWKSDocuments(t *testing.T) {
	f := signing(t, "kid")
	invalid := []any{nil, map[string]any{}, map[string]any{"keys": []any{}}, map[string]any{"keys": nil}, map[string]any{"keys": []any{f.jwk, f.jwk}}, map[string]any{"keys": []any{nil}}, map[string]any{"keys": []any{"text"}}}
	tooMany := make([]any, 17)
	for i := range tooMany {
		tooMany[i] = f.jwk
	}
	invalid = append(invalid, map[string]any{"keys": tooMany})
	for _, override := range []map[string]any{{"kty": "RSA"}, {"crv": "X25519"}, {"kid": nil}, {"kid": ""}, {"kid": strings.Repeat("a", 129)}, {"x": "bad="}, {"x": "YQ"}, {"x": nil}, {"alg": "none"}, {"alg": nil}, {"use": "enc"}, {"use": nil}, {"d": "private"}, {"d": nil}} {
		key := map[string]any{}
		for k, v := range f.jwk {
			key[k] = v
		}
		for k, v := range override {
			key[k] = v
		}
		invalid = append(invalid, map[string]any{"keys": []any{key}})
	}
	for i, body := range invalid {
		t.Run(fmt.Sprintf("case_%02d", i), func(t *testing.T) {
			v := testVerifier(t, f, func(o *Options) {
				o.Client = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { return response(string(marshal(t, body)), 200), nil })}
			})
			rejected(t, v, f.token(t, nil, nil), ErrJWKSUnavailable)
		})
	}
	optional := map[string]any{}
	for k, value := range f.jwk {
		if k != "alg" && k != "use" {
			optional[k] = value
		}
	}
	v := testVerifier(t, f, func(o *Options) {
		o.Client = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			return response(string(marshal(t, map[string]any{"keys": []any{optional}})), 200), nil
		})}
	})
	if _, err := v.Verify(context.Background(), f.token(t, nil, nil)); err != nil {
		t.Fatal(err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("broken stream") }

type trackedBody struct {
	io.Reader
	closed *atomic.Bool
}

func (b trackedBody) Close() error { b.closed.Store(true); return nil }
func TestBoundedResponseAndTransportFailures(t *testing.T) {
	f := signing(t, "kid")
	cases := []struct {
		name   string
		status int
		body   string
		length int64
		reader io.Reader
	}{
		{"unavailable", 503, "{}", 2, nil}, {"malformed JSON", 200, "{", 1, nil}, {"empty body", 204, "", 0, nil},
		{"advertised length", 200, "{}", 65537, nil}, {"stream limit", 200, strings.Repeat("x", 65537), -1, nil}, {"broken read", 200, "", -1, failingReader{}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var closed atomic.Bool
			v := testVerifier(t, f, func(o *Options) {
				o.Client = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
					reader := tt.reader
					if reader == nil {
						reader = strings.NewReader(tt.body)
					}
					return &http.Response{StatusCode: tt.status, ContentLength: tt.length, Header: make(http.Header), Body: trackedBody{reader, &closed}}, nil
				})}
			})
			rejected(t, v, f.token(t, nil, nil), ErrJWKSUnavailable)
			if !closed.Load() {
				t.Fatal("upstream body not closed")
			}
		})
	}
	v := testVerifier(t, f, func(o *Options) { o.URL = "://invalid" })
	rejected(t, v, f.token(t, nil, nil), ErrJWKSUnavailable)
	v = testVerifier(t, f, func(o *Options) { o.URL = "file:///etc/secret"; o.Client = &http.Client{} })
	rejected(t, v, f.token(t, nil, nil), ErrJWKSUnavailable)
}

func TestDefaultsAndRedirects(t *testing.T) {
	f := signing(t, "kid")
	body := marshal(t, map[string]any{"keys": []any{f.jwk}})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			t.Error("JWKS fetch sent cookies from the caller's client")
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/keys", 302)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	v := New(Options{URL: server.URL + "/keys"})
	now := time.Now().Unix()
	token := f.token(t, map[string]any{"iat": now, "exp": now + 60}, nil)
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if v.timeout != 3*time.Second || v.cacheTTL != 300*time.Second || v.refreshInterval != 5*time.Second {
		t.Fatal("incorrect defaults")
	}
	var originalPolicy atomic.Bool
	original := &http.Client{Timeout: time.Hour, CheckRedirect: func(*http.Request, []*http.Request) error { originalPolicy.Store(true); return nil }}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyURL, err := http.NewRequest(http.MethodGet, server.URL+"/keys", nil)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(keyURL.URL, []*http.Cookie{{Name: "sid", Value: "private"}})
	original.Jar = jar
	shared := New(Options{URL: server.URL + "/keys", Client: original})
	if _, err := shared.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if original.Jar != jar {
		t.Fatal("constructor mutated the caller's cookie jar")
	}
	redirect := New(Options{URL: server.URL + "/redirect", Client: original})
	rejected(t, redirect, token, ErrJWKSUnavailable)
	if original.Timeout != time.Hour {
		t.Fatal("constructor mutated supplied client")
	}
	if originalPolicy.Load() {
		t.Fatal("original redirect policy was used")
	}
}

func TestCredentialMarkerIsOptionalForMetadataAndStrictWhenPresent(t *testing.T) {
	f := signing(t, "credential")
	v := testVerifier(t, f, nil)
	for _, perms := range [][]string{{"banwords:dictionaries:read"}, {"superadmin"}} {
		session, err := v.Verify(context.Background(), f.token(t, map[string]any{"perms": perms}, nil))
		if err != nil || session.Credential != "" {
			t.Fatal("session claims changed")
		}
		service, err := v.Verify(context.Background(), f.token(t, map[string]any{"perms": perms, "credential": "service-token"}, nil))
		if err != nil || service.Credential != "service-token" {
			t.Fatal("service credential lost")
		}
	}
	for _, value := range []any{nil, false, 1, "", "session", "cookie", "Service-Token", []any{"service-token"}} {
		rejected(t, v, f.token(t, map[string]any{"credential": value}, nil), ErrInvalidToken)
	}
	// A case alias does not mark a session as service-token.
	got, err := v.Verify(context.Background(), f.token(t, map[string]any{"Credential": "service-token"}, nil))
	if err != nil || got.Credential != "" {
		t.Fatal("case-insensitive credential alias accepted")
	}
}
