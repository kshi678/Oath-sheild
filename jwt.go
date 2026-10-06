package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

var ErrInvalidToken = errors.New("invalid token")

type Claims struct {
	TokenType string `json:"typ"`
	jwt.RegisteredClaims
}

// Manager signs and verifies tokens. Access and refresh tokens use separate
// secrets, and each token carries a type claim, so one can never be used as the other.
type Manager struct {
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
	issuer        string
	parser        *jwt.Parser
}

func NewManager(accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration, issuer string) *Manager {
	return &Manager{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
		issuer:        issuer,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{"HS256"}),
			jwt.WithIssuer(issuer),
			jwt.WithExpirationRequired(),
			jwt.WithLeeway(5*time.Second),
		),
	}
}

func (m *Manager) AccessTTL() time.Duration { return m.accessTTL }

func (m *Manager) GenerateAccess(userID uuid.UUID) (string, time.Time, error) {
	return m.sign(m.accessSecret, TokenTypeAccess, userID, uuid.New(), m.accessTTL)
}

func (m *Manager) GenerateRefresh(userID uuid.UUID) (token string, jti uuid.UUID, exp time.Time, err error) {
	jti = uuid.New()
	token, exp, err = m.sign(m.refreshSecret, TokenTypeRefresh, userID, jti, m.refreshTTL)
	return
}

func (m *Manager) ParseAccess(token string) (*Claims, error) {
	return m.parse(token, m.accessSecret, TokenTypeAccess)
}

func (m *Manager) ParseRefresh(token string) (*Claims, error) {
	return m.parse(token, m.refreshSecret, TokenTypeRefresh)
}

func (m *Manager) sign(secret []byte, typ string, userID, jti uuid.UUID, ttl time.Duration) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)
	claims := Claims{
		TokenType: typ,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			ID:        jti.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	return s, exp, err
}

func (m *Manager) parse(token string, secret []byte, typ string) (*Claims, error) {
	claims := &Claims{}
	_, err := m.parser.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return secret, nil })
	if err != nil || claims.TokenType != typ {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
