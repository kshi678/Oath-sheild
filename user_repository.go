package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yourname/goauth-shield/internal/models"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrEmailTaken = errors.New("email already registered")
)

type UserRepository struct{ pool *pgxpool.Pool }

func NewUserRepository(pool *pgxpool.Pool) *UserRepository { return &UserRepository{pool: pool} }

func (r *UserRepository) Create(ctx context.Context, u *models.User) error {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO users (email, name, password_hash)
		 VALUES ($1, $2, $3)
		 RETURNING id, created_at, updated_at`,
		u.Email, u.Name, u.PasswordHash,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrEmailTaken
	}
	return err
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	return r.scanOne(r.pool.QueryRow(ctx,
		`SELECT id, email, name, password_hash, created_at, updated_at FROM users WHERE email = $1`, email))
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return r.scanOne(r.pool.QueryRow(ctx,
		`SELECT id, email, name, password_hash, created_at, updated_at FROM users WHERE id = $1`, id))
}

func (r *UserRepository) scanOne(row pgx.Row) (*models.User, error) {
	var u models.User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}
