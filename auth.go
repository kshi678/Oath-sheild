package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/yourname/goauth-shield/internal/auth"
	"github.com/yourname/goauth-shield/internal/config"
	"github.com/yourname/goauth-shield/internal/httpx"
	"github.com/yourname/goauth-shield/internal/middleware"
	"github.com/yourname/goauth-shield/internal/models"
	"github.com/yourname/goauth-shield/internal/repository"
)

type AuthHandler struct {
	users     *repository.UserRepository
	tokens    *repository.TokenRepository
	jwt       *auth.Manager
	cfg       *config.Config
	dummyHash string // compared against when the email is unknown, to equalise timing
}

func NewAuthHandler(u *repository.UserRepository, t *repository.TokenRepository, jm *auth.Manager, cfg *config.Config) (*AuthHandler, error) {
	dummy, err := auth.HashPassword("dummy-password-for-timing", cfg.BcryptCost)
	if err != nil {
		return nil, err
	}
	return &AuthHandler{users: u, tokens: t, jwt: jm, cfg: cfg, dummyHash: dummy}, nil
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type authResponse struct {
	User   *models.User  `json:"user"`
	Tokens tokenResponse `json:"tokens"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	name := strings.TrimSpace(req.Name)

	if !validEmail(email) {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_email", "a valid email is required")
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_password", err.Error())
		return
	}
	if utf8.RuneCountInString(name) > 100 {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_name", "name must be at most 100 characters")
		return
	}

	hash, err := auth.HashPassword(req.Password, h.cfg.BcryptCost)
	if err != nil {
		h.internalError(w, "hash password", err)
		return
	}
	user := &models.User{Email: email, Name: name, PasswordHash: hash}
	if err := h.users.Create(r.Context(), user); err != nil {
		if errors.Is(err, repository.ErrEmailTaken) {
			httpx.WriteError(w, http.StatusConflict, "email_taken", "email already registered")
			return
		}
		h.internalError(w, "create user", err)
		return
	}
	tokens, err := h.issueTokens(r.Context(), user.ID)
	if err != nil {
		h.internalError(w, "issue tokens", err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, authResponse{User: user, Tokens: tokens})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))

	user, err := h.users.GetByEmail(r.Context(), email)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		auth.CheckPassword(h.dummyHash, req.Password) // burn equivalent CPU time
		h.invalidCredentials(w)
		return
	case err != nil:
		h.internalError(w, "get user", err)
		return
	}
	if !auth.CheckPassword(user.PasswordHash, req.Password) {
		h.invalidCredentials(w)
		return
	}
	tokens, err := h.issueTokens(r.Context(), user.ID)
	if err != nil {
		h.internalError(w, "issue tokens", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, authResponse{User: user, Tokens: tokens})
}

// Refresh rotates the refresh token: the old one is consumed and a new pair is issued.
// Presenting an already-used token revokes every session of that user.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	_, userID, jti, ok := h.parseRefreshRequest(w, r)
	if !ok {
		return
	}

	consumed, err := h.tokens.Consume(r.Context(), jti, userID)
	if err != nil {
		h.internalError(w, "consume refresh token", err)
		return
	}
	if !consumed {
		slog.Warn("refresh token reuse or invalid jti; revoking all sessions", "user_id", userID)
		if err := h.tokens.RevokeAllForUser(r.Context(), userID); err != nil {
			h.internalError(w, "revoke sessions", err)
			return
		}
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "refresh token is no longer valid")
		return
	}
	if _, err := h.users.GetByID(r.Context(), userID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "refresh token is no longer valid")
			return
		}
		h.internalError(w, "get user", err)
		return
	}
	tokens, err := h.issueTokens(r.Context(), userID)
	if err != nil {
		h.internalError(w, "issue tokens", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, tokens)
}

// Logout revokes the supplied refresh token (idempotent).
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	_, userID, jti, ok := h.parseRefreshRequest(w, r)
	if !ok {
		return
	}
	if _, err := h.tokens.Consume(r.Context(), jti, userID); err != nil {
		h.internalError(w, "revoke refresh token", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// LogoutAll (protected) revokes every refresh token of the caller.
func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "not authenticated")
		return
	}
	if err := h.tokens.RevokeAllForUser(r.Context(), userID); err != nil {
		h.internalError(w, "revoke sessions", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) parseRefreshRequest(w http.ResponseWriter, r *http.Request) (*auth.Claims, uuid.UUID, uuid.UUID, bool) {
	var req refreshRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return nil, uuid.Nil, uuid.Nil, false
	}
	claims, err := h.jwt.ParseRefresh(req.RefreshToken)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired refresh token")
		return nil, uuid.Nil, uuid.Nil, false
	}
	userID, err1 := uuid.Parse(claims.Subject)
	jti, err2 := uuid.Parse(claims.ID)
	if err1 != nil || err2 != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "invalid refresh token")
		return nil, uuid.Nil, uuid.Nil, false
	}
	return claims, userID, jti, true
}

func (h *AuthHandler) issueTokens(ctx context.Context, userID uuid.UUID) (tokenResponse, error) {
	access, _, err := h.jwt.GenerateAccess(userID)
	if err != nil {
		return tokenResponse{}, err
	}
	refresh, jti, exp, err := h.jwt.GenerateRefresh(userID)
	if err != nil {
		return tokenResponse{}, err
	}
	if err := h.tokens.Store(ctx, jti, userID, exp); err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.jwt.AccessTTL().Seconds()),
	}, nil
}

func (h *AuthHandler) invalidCredentials(w http.ResponseWriter) {
	httpx.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
}

func (h *AuthHandler) internalError(w http.ResponseWriter, op string, err error) {
	slog.Error("handler error", "op", op, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "internal server error")
}

func validEmail(email string) bool {
	if email == "" || len(email) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Address == email
}
