package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func newTestManager() *Manager {
	return NewManager(strings.Repeat("a", 32), strings.Repeat("b", 32), time.Minute, time.Hour, "test")
}

func TestAccessAndRefreshAreNotInterchangeable(t *testing.T) {
	m := newTestManager()
	uid := uuid.New()

	access, _, err := m.GenerateAccess(uid)
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := m.GenerateRefresh(uid)
	if err != nil {
		t.Fatal(err)
	}

	if c, err := m.ParseAccess(access); err != nil || c.Subject != uid.String() {
		t.Fatalf("valid access token rejected: %v", err)
	}
	if _, err := m.ParseAccess(refresh); err == nil {
		t.Fatal("refresh token accepted as access token")
	}
	if _, err := m.ParseRefresh(access); err == nil {
		t.Fatal("access token accepted as refresh token")
	}
	if _, err := m.ParseAccess(access + "x"); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse", bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse") || CheckPassword(h, "wrong") {
		t.Fatal("password check failed")
	}
	if ValidatePassword("short") == nil || ValidatePassword(strings.Repeat("x", 73)) == nil {
		t.Fatal("length validation failed")
	}
}
