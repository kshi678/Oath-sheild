package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yourname/goauth-shield/internal/auth"
	"github.com/yourname/goauth-shield/internal/config"
	"github.com/yourname/goauth-shield/internal/database"
	"github.com/yourname/goauth-shield/internal/handlers"
	"github.com/yourname/goauth-shield/internal/httpx"
	"github.com/yourname/goauth-shield/internal/middleware"
	"github.com/yourname/goauth-shield/internal/repository"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool); err != nil {
		return err
	}

	userRepo := repository.NewUserRepository(pool)
	tokenRepo := repository.NewTokenRepository(pool)
	jwtManager := auth.NewManager(cfg.JWTAccessSecret, cfg.JWTRefreshSecret, cfg.AccessTTL, cfg.RefreshTTL, cfg.JWTIssuer)

	authHandler, err := handlers.NewAuthHandler(userRepo, tokenRepo, jwtManager, cfg)
	if err != nil {
		return err
	}
	userHandler := handlers.NewUserHandler(userRepo)

	globalLimiter := middleware.NewRateLimiter(ctx, cfg.RateLimitRPS, cfg.RateLimitBurst, cfg.TrustProxy)
	authLimiter := middleware.NewRateLimiter(ctx, cfg.AuthRateLimitRPS, cfg.AuthRateLimitBurst, cfg.TrustProxy)
	requireAuth := middleware.Authenticate(jwtManager)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", readyHandler(pool))

	// Public auth routes: stricter per-IP limit (also slows password guessing).
	mux.Handle("POST /api/v1/auth/register", authLimiter.Middleware(http.HandlerFunc(authHandler.Register)))
	mux.Handle("POST /api/v1/auth/login", authLimiter.Middleware(http.HandlerFunc(authHandler.Login)))
	mux.Handle("POST /api/v1/auth/refresh", authLimiter.Middleware(http.HandlerFunc(authHandler.Refresh)))
	mux.Handle("POST /api/v1/auth/logout", authLimiter.Middleware(http.HandlerFunc(authHandler.Logout)))

	// Protected routes.
	mux.Handle("POST /api/v1/auth/logout-all", requireAuth(http.HandlerFunc(authHandler.LogoutAll)))
	mux.Handle("GET /api/v1/users/me", requireAuth(http.HandlerFunc(userHandler.Me)))

	handler := middleware.Chain(mux,
		middleware.Recoverer,
		middleware.SecurityHeaders,
		middleware.RequestLogger(cfg.TrustProxy),
		globalLimiter.Middleware,
	)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	go cleanupTokens(ctx, tokenRepo)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("server starting", "addr", srv.Addr, "env", cfg.Env)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func readyHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			httpx.WriteError(w, http.StatusServiceUnavailable, "not_ready", "database unavailable")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

func cleanupTokens(ctx context.Context, tokens *repository.TokenRepository) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := tokens.DeleteExpired(ctx)
			if err != nil {
				slog.Error("token cleanup failed", "err", err)
				continue
			}
			slog.Info("expired refresh tokens removed", "count", n)
		}
	}
}
