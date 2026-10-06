package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/yourname/goauth-shield/internal/httpx"
	"github.com/yourname/goauth-shield/internal/middleware"
	"github.com/yourname/goauth-shield/internal/repository"
)

type UserHandler struct{ users *repository.UserRepository }

func NewUserHandler(u *repository.UserRepository) *UserHandler { return &UserHandler{users: u} }

// Me returns the authenticated user's profile.
func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	id, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "not authenticated")
		return
	}
	user, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "account no longer exists")
			return
		}
		slog.Error("get user", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user": user})
}
