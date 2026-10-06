package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TokenRepository struct{ pool *pgxpool.Pool }

func NewTokenRepository(pool *pgxpool.Pool) *TokenRepository { return &TokenRepository{pool: pool} }

func (r *TokenRepository) Store(ctx context.Context, jti, userID uuid.UUID, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (id, user_id, expires_at) VALUES ($1, $2, $3)`,
		jti, userID, expiresAt)
	return err
}

// Consume atomically revokes a live refresh token. It returns false when the
// token is unknown, expired, belongs to someone else, or was already used —
// the last case indicates possible token theft (reuse).
func (r *TokenRepository) Consume(ctx context.Context, jti, userID uuid.UUID) (bool, error) {
	tag, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now()
		 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()`,
		jti, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (r *TokenRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

func (r *TokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
