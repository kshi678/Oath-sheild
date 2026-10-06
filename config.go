package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Env         string
	Port        string
	TrustProxy  bool
	DatabaseURL string

	JWTAccessSecret  string
	JWTRefreshSecret string
	JWTIssuer        string
	AccessTTL        time.Duration
	RefreshTTL       time.Duration

	BcryptCost int

	RateLimitRPS       float64
	RateLimitBurst     int
	AuthRateLimitRPS   float64
	AuthRateLimitBurst int
}

func (c *Config) IsProduction() bool { return c.Env == "production" }

// Load reads configuration from the environment (and .env if present).
func Load() (*Config, error) {
	_ = godotenv.Load() // optional

	var errs []error
	check := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	c := &Config{
		Env:              getEnv("APP_ENV", "development"),
		Port:             getEnv("PORT", "8080"),
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		JWTAccessSecret:  os.Getenv("JWT_ACCESS_SECRET"),
		JWTRefreshSecret: os.Getenv("JWT_REFRESH_SECRET"),
		JWTIssuer:        getEnv("JWT_ISSUER", "goauth-shield"),
	}
	var err error
	c.TrustProxy, err = getBool("TRUST_PROXY", false)
	check(err)
	c.AccessTTL, err = getDuration("ACCESS_TOKEN_TTL", 15*time.Minute)
	check(err)
	c.RefreshTTL, err = getDuration("REFRESH_TOKEN_TTL", 168*time.Hour)
	check(err)
	c.BcryptCost, err = getInt("BCRYPT_COST", 12)
	check(err)
	c.RateLimitRPS, err = getFloat("RATE_LIMIT_RPS", 10)
	check(err)
	c.RateLimitBurst, err = getInt("RATE_LIMIT_BURST", 20)
	check(err)
	c.AuthRateLimitRPS, err = getFloat("AUTH_RATE_LIMIT_RPS", 0.5)
	check(err)
	c.AuthRateLimitBurst, err = getInt("AUTH_RATE_LIMIT_BURST", 5)
	check(err)

	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if len(c.JWTAccessSecret) < 32 {
		errs = append(errs, errors.New("JWT_ACCESS_SECRET must be at least 32 characters"))
	}
	if len(c.JWTRefreshSecret) < 32 {
		errs = append(errs, errors.New("JWT_REFRESH_SECRET must be at least 32 characters"))
	}
	if c.JWTAccessSecret == c.JWTRefreshSecret {
		errs = append(errs, errors.New("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must differ"))
	}
	if c.BcryptCost < 10 || c.BcryptCost > 15 {
		errs = append(errs, errors.New("BCRYPT_COST must be between 10 and 15"))
	}
	if c.RateLimitRPS <= 0 || c.AuthRateLimitRPS <= 0 || c.RateLimitBurst < 1 || c.AuthRateLimitBurst < 1 {
		errs = append(errs, errors.New("rate limit values must be positive"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return c, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getBool(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}

func getInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func getFloat(key string, def float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def, fmt.Errorf("%s: %w", key, err)
	}
	return f, nil
}

func getDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}
