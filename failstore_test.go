package oauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"smeldr.dev/oauth"
)

// failStore wraps a real *oauth.SQLiteStore and forces chosen Save* calls to
// fail, exercising the "internal error" branches in authorize.go/token.go
// that a real SQLiteStore essentially never hits under test.
type failStore struct {
	*oauth.SQLiteStore
	failSaveCode         bool
	failSaveToken        bool
	failSaveRefreshToken bool
}

var errForced = errors.New("oauth test: forced store failure")

func (f *failStore) SaveCode(ctx context.Context, c oauth.AuthCode) error {
	if f.failSaveCode {
		return errForced
	}
	return f.SQLiteStore.SaveCode(ctx, c)
}

func (f *failStore) SaveToken(ctx context.Context, t oauth.AccessToken) error {
	if f.failSaveToken {
		return errForced
	}
	return f.SQLiteStore.SaveToken(ctx, t)
}

func (f *failStore) SaveRefreshToken(ctx context.Context, t oauth.RefreshToken) error {
	if f.failSaveRefreshToken {
		return errForced
	}
	return f.SQLiteStore.SaveRefreshToken(ctx, t)
}

// newFailTestServer mirrors newTestServer but is backed by a *failStore so
// individual Save* calls can be forced to fail.
func newFailTestServer(t *testing.T, fs *failStore) *httptest.Server {
	t.Helper()

	var ts *httptest.Server
	var oauthHandler http.Handler
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			doc := map[string]any{
				"client_id":     ts.URL,
				"client_name":   "Fail Store Test Client",
				"redirect_uris": []string{ts.URL + "/callback"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(doc) //nolint:errcheck
			return
		}
		if oauthHandler != nil {
			oauthHandler.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(ts.Close)

	srv := oauth.New(oauth.Config{
		Issuer:       ts.URL,
		Resource:     ts.URL + "/mcp",
		VerifyBearer: func(string) bool { return true },
		HTTPClient:   ts.Client(),
	}, fs)
	oauthHandler = srv.Handler()
	return ts
}

func newFailStore(t *testing.T) *failStore {
	t.Helper()
	store, err := oauth.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return &failStore{SQLiteStore: store}
}

func TestAuthorizePost_SaveCodeFails(t *testing.T) {
	fs := newFailStore(t)
	fs.failSaveCode = true
	ts := newFailTestServer(t, fs)
	_, challenge := testPKCE()

	form := map[string][]string{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"bearer_token":          {"valid-forge-token"},
		"resource":              {ts.URL + "/mcp"},
	}
	resp, err := ts.Client().PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", resp.StatusCode)
	}
}

func TestTokenExchange_SaveTokenFails(t *testing.T) {
	fs := newFailStore(t)
	ts := newFailTestServer(t, fs)
	verifier, challenge := testPKCE()

	code := "test-code-savetoken-fails"
	_ = fs.SQLiteStore.SaveCode(context.Background(), oauth.AuthCode{
		Code:          code,
		ClientID:      ts.URL,
		RedirectURI:   ts.URL + "/callback",
		Scope:         "mcp",
		CodeChallenge: challenge,
		Resource:      ts.URL + "/mcp",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})
	fs.failSaveToken = true

	resp := postToken(t, ts.Client(), ts.URL, map[string][]string{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {ts.URL},
		"redirect_uri":  {ts.URL + "/callback"},
		"code_verifier": {verifier},
		"resource":      {ts.URL + "/mcp"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", resp.StatusCode)
	}
}

func TestTokenExchange_SaveRefreshTokenFails(t *testing.T) {
	fs := newFailStore(t)
	ts := newFailTestServer(t, fs)
	verifier, challenge := testPKCE()

	code := "test-code-saverefresh-fails"
	_ = fs.SQLiteStore.SaveCode(context.Background(), oauth.AuthCode{
		Code:          code,
		ClientID:      ts.URL,
		RedirectURI:   ts.URL + "/callback",
		Scope:         "mcp offline_access",
		CodeChallenge: challenge,
		Resource:      ts.URL + "/mcp",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})
	fs.failSaveRefreshToken = true

	resp := postToken(t, ts.Client(), ts.URL, map[string][]string{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {ts.URL},
		"redirect_uri":  {ts.URL + "/callback"},
		"code_verifier": {verifier},
		"resource":      {ts.URL + "/mcp"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", resp.StatusCode)
	}
}

func TestTokenRefresh_SaveTokenFails(t *testing.T) {
	fs := newFailStore(t)
	ts := newFailTestServer(t, fs)

	refreshToken := "test-refresh-savetoken-fails"
	_ = fs.SQLiteStore.SaveRefreshToken(context.Background(), oauth.RefreshToken{
		Token:    refreshToken,
		ClientID: ts.URL,
		Scope:    "mcp",
	})
	fs.failSaveToken = true

	resp := postToken(t, ts.Client(), ts.URL, map[string][]string{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {ts.URL},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", resp.StatusCode)
	}
}
