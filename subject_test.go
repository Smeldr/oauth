package oauth_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"smeldr.dev/oauth"
)

// core T1287 (D193) and T1285: an access token acts as the person whose token
// was pasted, never as more, and a refresh token rotates.

// subjectFlow is a server with one registered client, and the subject its
// ResolveBearer and TokenActive answer.
type subjectFlow struct {
	t        *testing.T
	ts       *httptest.Server
	store    *oauth.SQLiteStore
	clientID string
	redirect string
	subject  oauth.Subject
	active   bool
}

func newSubjectFlow(t *testing.T, sub oauth.Subject) *subjectFlow {
	t.Helper()
	store, err := oauth.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	f := &subjectFlow{t: t, store: store, subject: sub, active: true, redirect: "https://client.example.com/cb"}
	var srv *oauth.Server
	mux := http.NewServeMux()
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	srv = oauth.New(oauth.Config{
		Issuer:   f.ts.URL,
		Resource: f.ts.URL + "/mcp",
		ResolveBearer: func(token string) (oauth.Subject, bool) {
			if token != "good" {
				return oauth.Subject{}, false
			}
			return f.subject, true
		},
		TokenActive: func(id string) (oauth.Subject, bool) {
			if !f.active || id != f.subject.TokenID {
				return oauth.Subject{}, false
			}
			return f.subject, true
		},
	}, store)
	mux.Handle("/", srv.Handler())
	resp, err := f.ts.Client().Post(f.ts.URL+"/oauth/register", "application/json",
		strings.NewReader(`{"redirect_uris": ["`+f.redirect+`"], "client_name": "Subject Client"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var reg map[string]any
	json.NewDecoder(resp.Body).Decode(&reg) //nolint:errcheck
	f.clientID, _ = reg["client_id"].(string)
	return f
}

// authorize posts the form and returns the status and the code (on 302).
func (f *subjectFlow) authorize(bearer, scope string) (int, string, string) {
	f.t.Helper()
	_, challenge := testPKCE()
	form := url.Values{
		"response_type": {"code"}, "client_id": {f.clientID}, "redirect_uri": {f.redirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "bearer_token": {bearer},
		"resource": {f.ts.URL + "/mcp"}, "scope": {scope},
	}
	client := f.ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.PostForm(f.ts.URL+"/oauth/authorize", form)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return resp.StatusCode, loc.Query().Get("code"), string(body)
}

// exchange trades a code for tokens: the status and the JSON answer.
func (f *subjectFlow) exchange(code string) (int, map[string]any) {
	f.t.Helper()
	verifier, _ := testPKCE()
	return f.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {f.clientID},
		"redirect_uri": {f.redirect}, "code_verifier": {verifier}, "resource": {f.ts.URL + "/mcp"}})
}

func (f *subjectFlow) refresh(rt string) (int, map[string]any) {
	f.t.Helper()
	return f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {f.clientID}})
}

func (f *subjectFlow) token(v url.Values) (int, map[string]any) {
	f.t.Helper()
	resp := postToken(f.t, f.ts.Client(), f.ts.URL, v)
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out) //nolint:errcheck
	return resp.StatusCode, out
}

func TestSubject_StoredOnTheAccessToken(t *testing.T) {
	soon := time.Now().Add(10 * time.Minute)
	f := newSubjectFlow(t, oauth.Subject{UserID: "u-1", TokenID: "fp-1", ExpiresAt: soon})
	status, code, body := f.authorize("good", "mcp offline_access")
	if status != http.StatusFound || code == "" {
		t.Fatalf("authorize = %d %s", status, body)
	}
	status, tok := f.exchange(code)
	if status != http.StatusOK {
		t.Fatalf("exchange = %d %v", status, tok)
	}
	at, err := f.store.GetToken(context.Background(), tok["access_token"].(string))
	if err != nil || at.UserID != "u-1" || at.TokenID != "fp-1" {
		t.Errorf("access token = %+v %v", at, err)
	}
	if at.ExpiresAt.After(soon.Add(time.Second)) {
		t.Errorf("the access token outlives its source token: %v after %v", at.ExpiresAt, soon)
	}
	if exp, _ := tok["expires_in"].(float64); exp > 601 {
		t.Errorf("expires_in = %v; want at most the source token's ten minutes", exp)
	}
	rt, err := f.store.GetRefreshToken(context.Background(), tok["refresh_token"].(string))
	if err != nil || rt.UserID != "u-1" || rt.ExpiresAt.After(soon.Add(time.Second)) {
		t.Errorf("refresh token = %+v %v", rt, err)
	}
}

func TestSubject_FormRefusals(t *testing.T) {
	f := newSubjectFlow(t, oauth.Subject{UserID: "u-1", TokenID: "fp-1"})
	// D195: a scope gives nothing and refuses nothing: any valid token signs
	// in, whatever the client asks for.
	if status, _, body := f.authorize("good", "mcp:admin"); status != http.StatusFound {
		t.Errorf("mcp:admin = %d %s; want a sign-in", status, body)
	}
	if status, _, body := f.authorize("bad", "mcp"); status != http.StatusUnauthorized ||
		!strings.Contains(body, "This token is not valid. Check that it is whole, and not revoked or expired.") {
		t.Errorf("a bad token = %d %s", status, body)
	}
	f.subject.UserID = ""
	if status, _, _ := f.authorize("good", "mcp"); status != http.StatusUnauthorized {
		t.Errorf("a subject with no user = %d", status)
	}
}

// A server wired with VerifyBearer only refuses at the form, in plain words.
func TestSubject_OldWiringRefusesAtTheForm(t *testing.T) {
	store, err := oauth.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mux := http.NewServeMux()
	old := httptest.NewServer(mux)
	defer old.Close()
	mux.Handle("/", oauth.New(oauth.Config{Issuer: old.URL, Resource: old.URL + "/mcp", VerifyBearer: func(string) bool { return true }}, store).Handler())
	f := &subjectFlow{t: t, ts: old, store: store, redirect: "https://client.example.com/cb"}
	resp, err := old.Client().Post(old.URL+"/oauth/register", "application/json",
		strings.NewReader(`{"redirect_uris": ["`+f.redirect+`"], "client_name": "Old"}`))
	if err != nil {
		t.Fatal(err)
	}
	var reg map[string]any
	json.NewDecoder(resp.Body).Decode(&reg) //nolint:errcheck
	resp.Body.Close()
	f.clientID, _ = reg["client_id"].(string)
	if status, code, body := f.authorize("anything", "mcp"); status != http.StatusServiceUnavailable || code != "" || !strings.Contains(body, "This server cannot connect a client yet. Ask its operator to update Smeldr.") {
		t.Errorf("old wiring = %d %q %s", status, code, body)
	}
}

func TestSubject_ExchangeRechecksTheToken(t *testing.T) {
	f := newSubjectFlow(t, oauth.Subject{UserID: "u-1", TokenID: "fp-1"})
	_, code, _ := f.authorize("good", "mcp")
	f.active = false
	if status, tok := f.exchange(code); status != http.StatusBadRequest || tok["error"] != "invalid_grant" {
		t.Errorf("exchange after the token was revoked = %d %v", status, tok)
	}
}

func TestRefresh_Rotates(t *testing.T) {
	f := newSubjectFlow(t, oauth.Subject{UserID: "u-1", TokenID: "fp-1"})
	_, code, _ := f.authorize("good", "mcp offline_access")
	_, tok := f.exchange(code)
	first := tok["refresh_token"].(string)
	status, again := f.refresh(first)
	second, _ := again["refresh_token"].(string)
	if status != http.StatusOK || second == "" || second == first {
		t.Fatalf("refresh = %d %v", status, again)
	}
	if status, out := f.refresh(first); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("the used refresh token again = %d %v", status, out)
	}
	if status, _ := f.refresh(second); status != http.StatusOK {
		t.Errorf("the new refresh token = %d", status)
	}
}

func TestRefresh_Refusals(t *testing.T) {
	f := newSubjectFlow(t, oauth.Subject{UserID: "u-1", TokenID: "fp-1"})
	ctx := context.Background()
	seed := func(token string, exp time.Time, tokenID string) {
		if err := f.store.SaveRefreshToken(ctx, oauth.RefreshToken{Token: token, ClientID: f.clientID, Scope: "mcp offline_access",
			ExpiresAt: exp, UserID: "u-1", TokenID: tokenID}); err != nil {
			t.Fatal(err)
		}
	}
	seed("expired", time.Now().Add(-time.Minute), "fp-1")
	seed("no-expiry", time.Time{}, "fp-1")
	seed("other-token", time.Now().Add(time.Hour), "fp-other")
	seed("revoked-source", time.Now().Add(time.Hour), "fp-1")
	for _, rt := range []string{"expired", "no-expiry", "other-token"} {
		if status, out := f.refresh(rt); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
			t.Errorf("%s = %d %v", rt, status, out)
		}
	}
	f.active = false
	if status, out := f.refresh("revoked-source"); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("revoked source = %d %v", status, out)
	}
	if _, err := f.store.GetRefreshToken(ctx, "expired"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("an expired refresh token is kept: %v", err)
	}
}

// Two uses of one refresh token: the store's rotation lets one succeed.
func TestRefresh_RotateIsAtomic(t *testing.T) {
	store, err := oauth.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.SaveRefreshToken(ctx, oauth.RefreshToken{Token: "old", ClientID: "c", Scope: "s", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := store.RotateRefreshToken(ctx, "old", oauth.RefreshToken{Token: "new-1", ClientID: "c", Scope: "s"}); err != nil {
		t.Fatal(err)
	}
	if err := store.RotateRefreshToken(ctx, "old", oauth.RefreshToken{Token: "new-2", ClientID: "c", Scope: "s"}); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("second rotation of one token = %v, want ErrRefreshTokenNotFound", err)
	}
	if _, err := store.GetRefreshToken(ctx, "new-2"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("the losing rotation saved its token: %v", err)
	}
}

// A database made before the subject columns gets them at open.
func TestSubject_MigratesAnOldDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE smeldr_oauth_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, scope TEXT NOT NULL, code_challenge TEXT NOT NULL, resource TEXT NOT NULL DEFAULT '', expires_at INTEGER NOT NULL)`,
		`CREATE TABLE smeldr_oauth_tokens (token TEXT PRIMARY KEY, client_id TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL DEFAULT '', expires_at INTEGER NOT NULL)`,
		`CREATE TABLE smeldr_oauth_refresh_tokens (token TEXT PRIMARY KEY, client_id TEXT NOT NULL, scope TEXT NOT NULL)`,
		`INSERT INTO smeldr_oauth_refresh_tokens (token, client_id, scope) VALUES ('legacy', 'c', 's')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	store, err := oauth.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rt, err := store.GetRefreshToken(context.Background(), "legacy")
	if err != nil || !rt.ExpiresAt.IsZero() || rt.UserID != "" {
		t.Errorf("legacy refresh token = %+v %v; want no expiry and no subject", rt, err)
	}
	if err := store.SaveToken(context.Background(), oauth.AccessToken{Token: "a", ClientID: "c", Scope: "s", ExpiresAt: time.Now(), UserID: "u", TokenID: "fp"}); err != nil {
		t.Errorf("save on the migrated table: %v", err)
	}
	if again, err := oauth.NewSQLiteStore(path); err != nil {
		t.Errorf("a second open: %v", err)
	} else {
		again.Close()
	}
}

func TestNew_SubjectWiring(t *testing.T) {
	for name, cfg := range map[string]oauth.Config{
		"neither":                {Issuer: "https://x", Resource: "https://x/mcp"},
		"resolve with no active": {Issuer: "https://x", Resource: "https://x/mcp", ResolveBearer: resolveWith(func(string) bool { return true })},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: New did not panic", name)
				}
			}()
			oauth.New(cfg, nil)
		}()
	}
}
