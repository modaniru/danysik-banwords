// Package httpapi implements the closed, read-only banwords HTTP contract.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/modaniru/danysik-banwords/internal/auth"
	"github.com/modaniru/danysik-banwords/internal/catalog"
)

const (
	CatalogPath = "/api/banwords/catalog"
	HashPath    = "/api/banwords/catalog/hash"
	OpenAPIPath = "/api/banwords/openapi.json"
	HealthPath  = "/healthz"
)

// Routes enumerates exactly the operations documented in openapi.json.
var Routes = [...]string{CatalogPath, HashPath, OpenAPIPath, HealthPath}

type Verifier interface {
	Verify(context.Context, string) (auth.Claims, error)
}

type Options struct {
	Catalog  *catalog.Catalog
	Verifier Verifier
	OpenAPI  []byte
	Limiter  *RateLimiter
	Logger   *slog.Logger
}

type handler struct {
	opts Options
	body []byte
	hash string
}

func New(opts Options) http.Handler {
	if opts.Limiter == nil {
		opts.Limiter = NewRateLimiter(LimiterOptions{})
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	// Snapshot caller-owned OpenAPI bytes and the immutable loaded catalog.
	opts.OpenAPI = append([]byte(nil), opts.OpenAPI...)
	return &handler{opts: opts, body: opts.Catalog.Body(), hash: opts.Catalog.Hash()}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	defer func() {
		if recover() != nil {
			h.internalError(w)
		}
	}()
	h.serve(w, r)
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	if path == HealthPath {
		if !allowGET(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	data := path == CatalogPath || path == HashPath
	if !data && path != OpenAPIPath {
		writeError(w, http.StatusNotFound, "не найдено")
		return
	}
	headers := r.Header.Values("X-Auth-Token")
	if len(headers) != 1 || headers[0] == "" {
		writeError(w, http.StatusNotFound, "не найдено")
		return
	}
	user, err := h.opts.Verifier.Verify(r.Context(), headers[0])
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidToken):
			writeError(w, http.StatusNotFound, "не найдено")
		case errors.Is(err, auth.ErrJWKSUnavailable):
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "авторизация временно недоступна")
		default:
			h.internalError(w)
		}
		return
	}
	// A signed session JWT, including superadmin, cannot read catalog data.
	// The credential marker is issued only after auth verifies a service token.
	if data && user.Credential != "service-token" {
		writeError(w, http.StatusNotFound, "не найдено")
		return
	}
	if retry := h.opts.Limiter.Take(user.Subject); retry != 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeError(w, http.StatusTooManyRequests, "слишком много запросов")
		return
	}
	if !allowGET(w, r) {
		return
	}
	switch path {
	case CatalogPath:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("ETag", `"`+h.hash+`"`)
		w.WriteHeader(http.StatusOK)
		// No second JSON encoding: Hash/ETag cover these exact response bytes.
		_, _ = w.Write(h.body)
	case HashPath:
		h.writeJSON(w, struct {
			Hash string `json:"hash"`
		}{h.hash})
	case OpenAPIPath:
		h.writeJSON(w, json.RawMessage(h.opts.OpenAPI))
	}
}

func allowGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
		return false
	}
	return true
}

func (h *handler) writeJSON(w http.ResponseWriter, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		h.internalError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	data, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{message})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func (h *handler) internalError(w http.ResponseWriter) {
	// Errors, panic values, headers, words and subjects may contain secrets.
	h.opts.Logger.Error("request failed")
	writeError(w, http.StatusInternalServerError, "внутренняя ошибка")
}
