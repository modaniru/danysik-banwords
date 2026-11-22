package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modaniru/danysik-banwords/internal/auth"
	"github.com/modaniru/danysik-banwords/internal/catalog"
)

type verifierFunc func(context.Context, string) (auth.Claims, error)

func (f verifierFunc) Verify(ctx context.Context, raw string) (auth.Claims, error) {
	return f(ctx, raw)
}
func setup(t *testing.T) Options {
	t.Helper()
	loaded, err := catalog.Load(os.DirFS("../../data"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := os.ReadFile("../../openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	return Options{Catalog: loaded, OpenAPI: spec, Verifier: verifierFunc(func(_ context.Context, raw string) (auth.Claims, error) {
		switch raw {
		case "valid":
			return auth.Claims{Subject: "123", Credential: "service-token", Permissions: []string{"banwords:dictionaries:read"}}, nil
		case "session":
			return auth.Claims{Subject: "123", Permissions: []string{"banwords:dictionaries:read"}}, nil
		case "superadmin":
			return auth.Claims{Subject: "123", Permissions: []string{"superadmin"}}, nil
		default:
			return auth.Claims{}, auth.ErrInvalidToken
		}
	})}
}
func request(h http.Handler, method, path string, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	for _, v := range headers {
		r.Header.Add("X-Auth-Token", v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestCatalogBodyHashETagAndOpenAPI(t *testing.T) {
	opts := setup(t)
	h := New(opts)
	for _, path := range []string{CatalogPath, HashPath, OpenAPIPath} {
		w := request(h, "GET", path, "valid")
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/json; charset=utf-8" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	body := request(h, "GET", CatalogPath, "valid")
	if !bytes.Equal(body.Body.Bytes(), opts.Catalog.Body()) {
		t.Fatal("catalog was encoded again")
	}
	sum := sha256.Sum256(body.Body.Bytes())
	hash := hex.EncodeToString(sum[:])
	if body.Header().Get("ETag") != `"`+hash+`"` {
		t.Fatal("ETag must hash exact body bytes")
	}
	fresh := request(h, "GET", HashPath, "valid")
	if !reflect.DeepEqual(decode(t, fresh.Body.Bytes()), map[string]any{"hash": hash}) || fresh.Header().Get("ETag") != "" {
		t.Fatal("freshness does not refer to full catalog")
	}
	value := decode(t, body.Body.Bytes())
	if len(value) != 4 || len(value["rules"].([]any)) != 22 {
		t.Fatal("full functional source data lost")
	}
	for _, entry := range value["rules"].([]any) {
		r := entry.(map[string]any)
		if len(r) != 5 || r["matchMode"] == nil || r["replaceMode"] == nil {
			t.Fatal("functional modes absent or client-only fields present")
		}
	}
	spec := decode(t, request(h, "GET", OpenAPIPath, "session").Body.Bytes())
	if !reflect.DeepEqual(spec, decode(t, opts.OpenAPI)) || spec["info"].(map[string]any)["version"] != "2.0.0" {
		t.Fatal("OpenAPI mismatch")
	}
	paths := spec["paths"].(map[string]any)
	got := []string{}
	for path, entry := range paths {
		got = append(got, path)
		methods := entry.(map[string]any)
		if len(methods) != 1 || methods["get"] == nil {
			t.Fatal("GET-only specification")
		}
		operation := methods["get"].(map[string]any)
		responses := operation["responses"].(map[string]any)
		statuses := []string{"405"}
		if path == HealthPath {
			statuses = append(statuses, "204")
		} else {
			statuses = append(statuses, "200", "404", "429", "500", "503")
		}
		for _, status := range statuses {
			if responses[status] == nil {
				t.Fatalf("%s missing status %s", path, status)
			}
		}
	}
	slices.Sort(got)
	want := slices.Clone(Routes[:])
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("spec routes %v != handlers %v", got, want)
	}
	if len(spec["security"].([]any)) != 1 {
		t.Fatal("data must permit only service bearer")
	}
	for _, path := range []string{CatalogPath, HashPath} {
		if _, exists := paths[path].(map[string]any)["get"].(map[string]any)["security"]; exists {
			t.Fatal("data must not allow cookie security")
		}
	}
	if len(paths[OpenAPIPath].(map[string]any)["get"].(map[string]any)["security"].([]any)) != 2 {
		t.Fatal("session must be able to obtain spec")
	}
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)
	if len(schemas) != 3 || schemas["Dictionary"] != nil {
		t.Fatal("old dictionary schema retained")
	}
	props := schemas["Catalog"].(map[string]any)["properties"].(map[string]any)
	rule := props["rules"].(map[string]any)["items"].(map[string]any)
	if len(props) != 4 || len(rule["properties"].(map[string]any)) != 5 || len(rule["required"].([]any)) != 5 {
		t.Fatal("functional schema changed")
	}
}

func TestServiceCredentialRequiredEvenForSuperadmin(t *testing.T) {
	h := New(setup(t))
	for _, token := range []string{"session", "superadmin"} {
		for _, path := range []string{CatalogPath, HashPath} {
			for _, method := range []string{"GET", "POST", "HEAD"} {
				w := request(h, method, path, token)
				if w.Code != 404 || w.Header().Get("ETag") != "" {
					t.Fatalf("session revealed data %s %s: %d", method, path, w.Code)
				}
			}
		}
		if request(h, "GET", OpenAPIPath, token).Code != 200 {
			t.Fatal("authenticated user cannot obtain OpenAPI")
		}
	}
	for _, path := range []string{CatalogPath, HashPath, OpenAPIPath} {
		for _, headers := range [][]string{nil, {""}, {"garbage"}, {"valid", "valid"}, {"valid", ""}} {
			if w := request(h, "GET", path, headers...); w.Code != 404 {
				t.Fatalf("untrusted header read %s: %d", path, w.Code)
			}
		}
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer bw_private")
		r.Header.Set("Cookie", "sid=superadmin")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal("service accepted external cookie or bearer directly")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := setup(t)
	opts.Verifier = verifierFunc(func(got context.Context, _ string) (auth.Claims, error) {
		if got != ctx {
			t.Fatal("verifier context replaced")
		}
		return auth.Claims{}, auth.ErrInvalidToken
	})
	r := httptest.NewRequest("GET", CatalogPath, nil).WithContext(ctx)
	r.Header.Set("X-Auth-Token", "valid")
	New(opts).ServeHTTP(httptest.NewRecorder(), r)
}

func TestMethodsHealthAndRemovedRoutes(t *testing.T) {
	h := New(setup(t))
	health := request(h, "GET", HealthPath)
	if health.Code != 204 || health.Body.Len() != 0 {
		t.Fatal("health")
	}
	for _, path := range Routes {
		for _, method := range []string{"POST", "PUT", "DELETE", "OPTIONS", "HEAD"} {
			w := request(h, method, path, "valid")
			if w.Code != 405 || w.Header().Get("Allow") != "GET" {
				t.Fatalf("%s %s: %d", method, path, w.Code)
			}
		}
	}
	for _, path := range []string{"/missing", "/api/banwords/docs", "/api/banwords/dictionaries/0dMf", "/api/banwords/dictionaries/", "/api/banwords/dictionaries/abcd/extra", CatalogPath + "/", HashPath + "/", CatalogPath + "%2fhash"} {
		for _, headers := range [][]string{nil, {"valid"}, {"session"}, {"superadmin"}} {
			if got := request(h, "GET", path, headers...).Code; got != 404 {
				t.Fatalf("removed or unknown %s: %d", path, got)
			}
		}
	}
	if request(h, "POST", CatalogPath).Code != 404 {
		t.Fatal("method revealed unauthenticated data route")
	}
}

func TestErrorsAndPanicsNeverExposeSecrets(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{{fmt.Errorf("private: %w", auth.ErrInvalidToken), 404}, {fmt.Errorf("private: %w", auth.ErrJWKSUnavailable), 503}, {errors.New("private material"), 500}} {
		opts := setup(t)
		var logs bytes.Buffer
		opts.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
		opts.Verifier = verifierFunc(func(context.Context, string) (auth.Claims, error) { return auth.Claims{}, tc.err })
		w := request(New(opts), "GET", CatalogPath, "valid")
		if w.Code != tc.status {
			t.Fatalf("error status: %d", w.Code)
		}
		if tc.status == 503 && w.Header().Get("Retry-After") != "5" {
			t.Fatal("retry header")
		}
		if strings.Contains(w.Body.String(), "private") || strings.Contains(logs.String(), "private") {
			t.Fatal("secret leak")
		}
		if (logs.Len() > 0) != (tc.status == 500) {
			t.Fatal("unexpected logging")
		}
	}
	for _, kind := range []string{"panic", "invalid-spec"} {
		opts := setup(t)
		var logs bytes.Buffer
		opts.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
		path := CatalogPath
		if kind == "panic" {
			opts.Verifier = verifierFunc(func(context.Context, string) (auth.Claims, error) { panic("private token") })
		} else {
			opts.OpenAPI = []byte("private broken JSON")
			path = OpenAPIPath
		}
		w := request(New(opts), "GET", path, "valid")
		if w.Code != 500 || w.Body.String() != `{"error":"внутренняя ошибка"}` || !strings.Contains(logs.String(), "request failed") || strings.Contains(logs.String(), "private") {
			t.Fatal("unsafe internal failure")
		}
	}
}

func TestSnapshotAndRealWire(t *testing.T) {
	opts := setup(t)
	h := New(opts)
	before := request(h, "GET", CatalogPath, "valid").Body.String()
	spec := request(h, "GET", OpenAPIPath, "valid").Body.String()
	for i := range opts.OpenAPI {
		opts.OpenAPI[i] = 'x'
	}
	body := opts.Catalog.Body()
	body[0] = '!'
	if request(h, "GET", CatalogPath, "valid").Body.String() != before || request(h, "GET", OpenAPIPath, "valid").Body.String() != spec {
		t.Fatal("caller changed HTTP snapshot")
	}
	server := httptest.NewServer(h)
	defer server.Close()
	r, err := http.NewRequest("GET", server.URL+CatalogPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Auth-Token", "valid")
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || string(data) != before {
		t.Fatal("wire bytes changed")
	}
	sum := sha256.Sum256(data)
	if response.Header.Get("ETag") != `"`+hex.EncodeToString(sum[:])+`"` {
		t.Fatal("wire ETag mismatch")
	}
}

func TestHTTPRateLimit(t *testing.T) {
	opts := setup(t)
	now := time.Unix(1000, 0)
	opts.Limiter = NewRateLimiter(LimiterOptions{Limit: 1, MaxUsers: 2, Now: func() time.Time { return now }})
	opts.Verifier = verifierFunc(func(_ context.Context, raw string) (auth.Claims, error) {
		return auth.Claims{Subject: raw, Credential: "service-token"}, nil
	})
	h := New(opts)
	if request(h, "GET", CatalogPath, "alice").Code != 200 {
		t.Fatal("first request")
	}
	w := request(h, "GET", HashPath, "alice")
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("rate header")
	}
	if request(h, "GET", OpenAPIPath, "bob").Code != 200 || request(h, "GET", CatalogPath, "carol").Code != 429 {
		t.Fatal("subject/memory bounds")
	}
	now = now.Add(time.Minute)
	if request(h, "GET", CatalogPath, "carol").Code != 200 {
		t.Fatal("window did not expire")
	}
}
func TestLimiterWindowBoundsAndDefaults(t *testing.T) {
	now := time.Unix(1, 0)
	l := NewRateLimiter(LimiterOptions{Limit: 1, Period: 1500 * time.Millisecond, MaxUsers: 1, Now: func() time.Time { return now }})
	if l.Take("alice") != 0 || l.Take("alice") != 2 || l.Take("bob") != 2 {
		t.Fatal("bounded fixed window")
	}
	now = now.Add(time.Second)
	if l.Take("alice") != 1 {
		t.Fatal("Retry-After must round up")
	}
	now = now.Add(500 * time.Millisecond)
	if l.Take("alice") != 0 {
		t.Fatal("same subject expiry")
	}
	now = now.Add(1500 * time.Millisecond)
	if l.Take("bob") != 0 || len(l.users) != 1 {
		t.Fatal("expired records not evicted")
	}
	defaults := NewRateLimiter(LimiterOptions{})
	for i := 0; i < 60; i++ {
		if defaults.Take("subject") != 0 {
			t.Fatal("default limit")
		}
	}
	if retry := defaults.Take("subject"); retry < 1 || retry > 60 {
		t.Fatalf("default retry %d", retry)
	}
	if retrySeconds(0) != 1 {
		t.Fatal("minimum retry")
	}
}

func TestLimiterConcurrentRequests(t *testing.T) {
	l := NewRateLimiter(LimiterOptions{Limit: 10})
	var accepted atomic.Int32
	var group sync.WaitGroup
	for range 100 {
		group.Go(func() {
			if l.Take("subject") == 0 {
				accepted.Add(1)
			}
		})
	}
	group.Wait()
	if accepted.Load() != 10 {
		t.Fatalf("accepted %d", accepted.Load())
	}
}

func TestSignedJWTThroughHTTPAndJWKS(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	var fetches atomic.Int32
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if r.URL.Path != "/keys" {
			t.Error("incorrect JWKS path")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"first","alg":"EdDSA","use":"sig","x":%q}]}`, base64.RawURLEncoding.EncodeToString(public))
	}))
	defer keys.Close()
	opts := setup(t)
	opts.Verifier = auth.New(auth.Options{URL: keys.URL + "/keys", Now: func() time.Time { return now }, CacheTTL: time.Minute})
	h := New(opts)
	issue := func(audience string, perms []string, expires int64, credential ...any) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT","kid":"first"}`))
		claims := map[string]any{"iss": "danysik-auth", "sub": "123", "aud": audience, "perms": perms, "iat": 1000, "exp": expires}
		if len(credential) > 0 {
			claims["credential"] = credential[0]
		}
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		signing := header + "." + base64.RawURLEncoding.EncodeToString(payload)
		return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(signing)))
	}
	token := issue("banwords", []string{"banwords:dictionaries:read"}, 1120, "service-token")
	if got := request(h, "GET", CatalogPath, token).Code; got != 200 {
		t.Fatalf("valid JWT got %d", got)
	}
	for _, bad := range []string{issue("other-service", []string{"banwords:dictionaries:read"}, 1120), issue("banwords", []string{"banwords"}, 1120), issue("banwords", []string{"banwords:dictionaries:read"}, 999)} {
		if got := request(h, "GET", CatalogPath, bad).Code; got != 404 {
			t.Fatalf("invalid claims got %d", got)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("JWKS cache: fetched %d times", fetches.Load())
	}
	for _, perms := range [][]string{{"banwords:dictionaries:read"}, {"superadmin"}} {
		session := issue("banwords", perms, 1120)
		for _, path := range []string{CatalogPath, HashPath} {
			if got := request(h, "GET", path, session).Code; got != 404 {
				t.Fatalf("session read data: %d", got)
			}
		}
		if got := request(h, "GET", OpenAPIPath, session).Code; got != 200 {
			t.Fatal("session cannot obtain OpenAPI")
		}
	}
	for _, credential := range []any{nil, "", false, "session", "Service-Token"} {
		bad := issue("banwords", []string{"superadmin"}, 1120, credential)
		if got := request(h, "GET", CatalogPath, bad).Code; got != 404 {
			t.Fatal("malformed credential accepted")
		}
	}
	keys.Close()
	if got := request(h, "GET", CatalogPath, token).Code; got != 200 {
		t.Fatalf("fresh cached keys got %d", got)
	}
	now = now.Add(61 * time.Second)
	unavailable := request(h, "GET", CatalogPath, token)
	if unavailable.Code != 503 || unavailable.Header().Get("Retry-After") != "5" {
		t.Fatalf("expired JWKS cache got %d", unavailable.Code)
	}
}
