package oauth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Failure paths of core T1287 (D193) and T1285.

func newRefreshStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRotateRefreshToken_Failures(t *testing.T) {
	ctx := context.Background()
	next := RefreshToken{Token: "next", ClientID: "c", Scope: "s"}

	s := newRefreshStore(t)
	if _, err := s.db.Exec(`CREATE TRIGGER no_insert BEFORE INSERT ON smeldr_oauth_refresh_tokens BEGIN SELECT RAISE(FAIL, 'refused'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER no_insert`); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRefreshToken(ctx, RefreshToken{Token: "old", ClientID: "c", Scope: "s"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER no_insert BEFORE INSERT ON smeldr_oauth_refresh_tokens BEGIN SELECT RAISE(FAIL, 'refused'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateRefreshToken(ctx, "old", next); err == nil {
		t.Error("a failed save rotated")
	}
	if _, err := s.GetRefreshToken(ctx, "old"); err != nil {
		t.Errorf("a failed rotation lost the old token: %v", err)
	}

	gone := newRefreshStore(t)
	if _, err := gone.db.Exec(`DROP TABLE smeldr_oauth_refresh_tokens`); err != nil {
		t.Fatal(err)
	}
	if err := gone.RotateRefreshToken(ctx, "old", next); err == nil || errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("a failed delete: %v", err)
	}

	closed := newRefreshStore(t)
	closed.db.Close()
	if err := closed.RotateRefreshToken(ctx, "old", next); err == nil {
		t.Error("a closed database rotated")
	}
}

func TestMigrateSubjectColumns_Failures(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// No tables: the first column cannot be added.
	if err := migrateAddSubjectColumns(ctx, db); err == nil || !strings.Contains(err.Error(), "smeldr_oauth_codes.user_id") {
		t.Errorf("err = %v", err)
	}
	db.Close()
	if err := migrateAddSubjectColumns(ctx, db); err != nil {
		t.Errorf("a database it cannot read is left alone: %v", err)
	}
}

// plainStore hides SQLiteStore's rotation, as another Store would.
type plainStore struct{ Store }

// rotateFails is a store whose rotation fails with err.
type rotateFails struct {
	*SQLiteStore
	err error
}

func (r rotateFails) RotateRefreshToken(context.Context, string, RefreshToken) error { return r.err }

func newSubjectServer(t *testing.T, store Store, active func(string) (Subject, bool)) *Server {
	t.Helper()
	return New(Config{
		Issuer: "https://x", Resource: "https://x/mcp",
		ResolveBearer: func(string) (Subject, bool) { return Subject{}, false },
		TokenActive:   active,
	}, store)
}

func refreshVia(t *testing.T, s *Server, rt string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"c"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func TestRefresh_RotationPaths(t *testing.T) {
	ctx := context.Background()
	sub := Subject{UserID: "u-1", TokenID: "fp-1"}
	active := func(id string) (Subject, bool) { return sub, id == "fp-1" }
	seed := func(s *SQLiteStore, token string) {
		t.Helper()
		if err := s.SaveRefreshToken(ctx, RefreshToken{Token: token, ClientID: "c", Scope: "mcp offline_access",
			ExpiresAt: time.Now().Add(time.Hour), UserID: "u-1", TokenID: "fp-1"}); err != nil {
			t.Fatal(err)
		}
	}

	// Another Store: rotated by delete and save, and the used token is gone.
	base := newRefreshStore(t)
	seed(base, "rt-plain")
	srv := newSubjectServer(t, plainStore{base}, active)
	if code, body := refreshVia(t, srv, "rt-plain"); code != http.StatusOK || !strings.Contains(body, "refresh_token") {
		t.Errorf("plain store refresh = %d %s", code, body)
	}
	if _, err := base.GetRefreshToken(ctx, "rt-plain"); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("the used token is kept: %v", err)
	}
	if err := srv.rotateRefreshToken(ctx, "missing", RefreshToken{Token: "x"}); err != nil {
		t.Logf("delete of a missing token: %v", err)
	}
	dropped := newRefreshStore(t)
	if _, err := dropped.db.Exec(`DROP TABLE smeldr_oauth_refresh_tokens`); err != nil {
		t.Fatal(err)
	}
	if err := newSubjectServer(t, plainStore{dropped}, active).rotateRefreshToken(ctx, "a", RefreshToken{Token: "b"}); err == nil {
		t.Error("a failed delete rotated")
	}

	// A rotation that loses the race is invalid_grant; another failure is 500.
	for _, c := range []struct {
		err  error
		code int
	}{{ErrRefreshTokenNotFound, http.StatusBadRequest}, {errors.New("disk"), http.StatusInternalServerError}} {
		s := newRefreshStore(t)
		seed(s, "rt")
		if code, body := refreshVia(t, newSubjectServer(t, rotateFails{s, c.err}, active), "rt"); code != c.code {
			t.Errorf("rotation %v = %d %s; want %d", c.err, code, body, c.code)
		}
	}

	// The token behind it now belongs to someone else: refused.
	other := newRefreshStore(t)
	seed(other, "rt-other")
	moved := func(string) (Subject, bool) { return Subject{UserID: "u-2"}, true }
	if code, _ := refreshVia(t, newSubjectServer(t, other, moved), "rt-other"); code != http.StatusBadRequest {
		t.Errorf("a source token of another user = %d", code)
	}
}
