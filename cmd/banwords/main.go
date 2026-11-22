package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	assets "github.com/modaniru/danysik-banwords"
	"github.com/modaniru/danysik-banwords/internal/auth"
	"github.com/modaniru/danysik-banwords/internal/catalog"
	"github.com/modaniru/danysik-banwords/internal/config"
	"github.com/modaniru/danysik-banwords/internal/httpapi"
)

// replaceable only within this package so tests can exercise the real entrypoint.
var exit = os.Exit

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.LookupEnv, os.Stdout); err != nil {
		// Configuration URLs and upstream errors can contain credentials.
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("startup or healthcheck failed")
		exit(1)
	}
}

func run(ctx context.Context, args []string, lookup func(string) (string, bool), output io.Writer) error {
	cfg, err := config.Load(lookup)
	if err != nil {
		return err
	}
	if len(args) > 0 {
		if len(args) != 1 || args[0] != "healthcheck" {
			return errors.New("unknown command")
		}
		return healthcheck(ctx, cfg.Port, &http.Client{Timeout: 3 * time.Second})
	}
	fsys := assets.BundledData()
	if cfg.DataDir != "" {
		fsys = os.DirFS(cfg.DataDir)
	}
	loaded, err := catalog.Load(fsys)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(output, nil))
	handler := httpapi.New(httpapi.Options{Catalog: loaded,
		Verifier: auth.New(auth.Options{URL: cfg.JWKSURL}), OpenAPI: assets.OpenAPI, Logger: logger})
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(cfg.Port))
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}
	logger.Info("banwords listening", "port", cfg.Port)
	return serve(ctx, server, listener, 10*time.Second)
}

func healthcheck(ctx context.Context, port int, client *http.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/healthz", port), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return errors.New("unhealthy service")
	}
	return nil
}

func serve(ctx context.Context, server *http.Server, listener net.Listener, timeout time.Duration) error {
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		return nil
	}
}
