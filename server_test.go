package oauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"smeldr.dev/oauth"
)

// testStore builds an in-memory SQLiteStore for tests.
func testStore(t *testing.T) *oauth.SQLiteStore {
	t.Helper()
	st, err := oauth.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// testPKCE returns a (verifier, challenge) pair.
func testPKCE() (verifier, challenge string) {
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // 43 chars, base64url-safe
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

// newTestServer creates an oauth TLS httptest.Server (https://).
// The CIMD metadata document is served by the test server itself:
// client_id == testServer.URL.
// The oauth Server is configured with ts.Client() as HTTPClient so
// that CIMD fetches trust the test TLS certificate.
func newTestServer(t *testing.T, verifyBearer func(string) bool) (*httptest.Server, *oauth.SQLiteStore) {
	t.Helper()
	store := testStore(t)

	var ts *httptest.Server
	// We need ts.URL for CIMD, but ts is not started yet.
	// Use a placeholder handler that is replaced after start.
	var oauthHandler http.Handler
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve CIMD document at the server root (client_id == ts.URL).
		if r.URL.Path == "/" {
			doc := map[string]any{
				"client_id":     ts.URL,
				"client_name":   "Test Client",
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
		VerifyBearer: verifyBearer,
		HTTPClient:   ts.Client(), // trusts the test TLS certificate
	}, store)
	oauthHandler = srv.Handler()
	return ts, store
}

// — Lag 1: unit tests —

func TestDiscovery(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	resp, err := ts.Client().Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	var meta map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got := meta["issuer"]; got != ts.URL {
		t.Errorf("issuer = %q, want %q", got, ts.URL)
	}
	if got := meta["authorization_endpoint"]; got != ts.URL+"/oauth/authorize" {
		t.Errorf("authorization_endpoint = %q", got)
	}
	if got := meta["token_endpoint"]; got != ts.URL+"/oauth/token" {
		t.Errorf("token_endpoint = %q", got)
	}
	methods, _ := meta["code_challenge_methods_supported"].([]any)
	if len(methods) == 0 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [S256]", methods)
	}
}

func TestAuthorizeGet_RendersForm(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	verifier, challenge := testPKCE()
	_ = verifier

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/callback"},
		"scope":                 {"mcp offline_access"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"abc123"},
	}
	resp, err := ts.Client().Get(ts.URL + "/oauth/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<form") {
		t.Error("response does not contain HTML form")
	}
	if !strings.Contains(string(body), challenge) {
		t.Error("form does not embed code_challenge")
	}
	if !strings.Contains(string(body), "Test Client") {
		t.Error("form does not show client_name")
	}
}

func TestAuthorizeGet_InvalidClientIDHTTP(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {"http://evil.example.com"},
		"redirect_uri":          {ts.URL + "/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	resp, err := ts.Client().Get(ts.URL + "/oauth/authorize?" + params.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeGet_InvalidClientIDNotURL(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {"not-a-url"},
		"redirect_uri":          {ts.URL + "/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	resp, err := ts.Client().Get(ts.URL + "/oauth/authorize?" + params.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeGet_CIMDFetchFailure(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {"https://unreachable.forge-test.invalid"},
		"redirect_uri":          {"https://unreachable.forge-test.invalid/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	resp, err := ts.Client().Get(ts.URL + "/oauth/authorize?" + params.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeGet_RedirectURINotInCIMD(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/not-listed"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	resp, err := ts.Client().Get(ts.URL + "/oauth/authorize?" + params.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizePost_ValidBearer(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/callback"},
		"scope":                 {"mcp offline_access"},
		"state":                 {"xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"bearer_token":          {"valid-forge-token"},
	}
	// Follow redirects manually to inspect the redirect URL.
	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatalf("POST authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want 302; body: %s", resp.StatusCode, body)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "code=") {
		t.Errorf("redirect location %q does not contain code=", loc)
	}
	if !strings.Contains(loc, "state=xyz") {
		t.Errorf("redirect location %q does not contain state=xyz", loc)
	}
}

func TestAuthorizePost_InvalidBearer(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return false })
	_, challenge := testPKCE()

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/callback"},
		"scope":                 {"mcp"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"bearer_token":          {"bad-token"},
	}
	resp, err := ts.Client().PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<form") {
		t.Error("expected re-rendered form on bearer failure")
	}
}

func TestPKCE_Verification(t *testing.T) {
	verifier, challenge := testPKCE()
	if !oauth.VerifyPKCE(verifier, challenge) {
		t.Error("VerifyPKCE: correct verifier should return true")
	}
	if oauth.VerifyPKCE("wrong-verifier", challenge) {
		t.Error("VerifyPKCE: wrong verifier should return false")
	}
}

func postToken(t *testing.T, client *http.Client, baseURL string, form url.Values) *http.Response {
	t.Helper()
	resp, err := client.PostForm(baseURL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	return resp
}

func TestTokenExchange_Valid(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })
	verifier, challenge := testPKCE()

	// Pre-store a valid auth code.
	code := "test-code-valid-001"
	_ = store.SaveCode(context.Background(), oauth.AuthCode{
		Code:          code,
		ClientID:      ts.URL,
		RedirectURI:   ts.URL + "/callback",
		Scope:         "mcp offline_access",
		CodeChallenge: challenge,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {ts.URL},
		"redirect_uri":  {ts.URL + "/callback"},
		"code_verifier": {verifier},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want 200; body: %s", resp.StatusCode, body)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["access_token"] == "" {
		t.Error("missing access_token")
	}
	if result["refresh_token"] == "" {
		t.Error("missing refresh_token (offline_access scope was present)")
	}
	if result["token_type"] != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", result["token_type"])
	}
}

func TestTokenExchange_ExpiredCode(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()
	verifier, _ := testPKCE()

	code := "test-code-expired-001"
	_ = store.SaveCode(context.Background(), oauth.AuthCode{
		Code:          code,
		ClientID:      ts.URL,
		RedirectURI:   ts.URL + "/callback",
		Scope:         "mcp",
		CodeChallenge: challenge,
		ExpiresAt:     time.Now().Add(-time.Minute), // already expired
	})

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {ts.URL},
		"redirect_uri":  {ts.URL + "/callback"},
		"code_verifier": {verifier},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["error"] != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", result["error"])
	}
}

func TestTokenExchange_WrongVerifier(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()

	code := "test-code-wrong-verifier-001"
	_ = store.SaveCode(context.Background(), oauth.AuthCode{
		Code:          code,
		ClientID:      ts.URL,
		RedirectURI:   ts.URL + "/callback",
		Scope:         "mcp",
		CodeChallenge: challenge,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {ts.URL},
		"redirect_uri":  {ts.URL + "/callback"},
		"code_verifier": {"wrong-verifier-value"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["error"] != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", result["error"])
	}
}

func TestTokenRefresh_Valid(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })

	refreshToken := "test-refresh-token-001"
	_ = store.SaveRefreshToken(context.Background(), oauth.RefreshToken{
		Token:    refreshToken,
		ClientID: ts.URL,
		Scope:    "mcp offline_access",
	})

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {ts.URL},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want 200; body: %s", resp.StatusCode, body)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["access_token"] == "" {
		t.Error("missing access_token in refresh response")
	}
}

func TestTokenRefresh_UnknownToken(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"nonexistent-refresh-token"},
		"client_id":     {ts.URL},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["error"] != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", result["error"])
	}
}

func TestValidateAccessToken_Valid(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })

	token := "test-access-token-valid"
	_ = store.SaveToken(context.Background(), oauth.AccessToken{
		Token:     token,
		ClientID:  ts.URL,
		Scope:     "mcp",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	srv := oauth.New(oauth.Config{
		Issuer:       ts.URL,
		VerifyBearer: func(string) bool { return true },
	}, store)

	at, err := srv.ValidateAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if at.ClientID != ts.URL {
		t.Errorf("ClientID = %q, want %q", at.ClientID, ts.URL)
	}
}

func TestValidateAccessToken_Expired(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })

	token := "test-access-token-expired"
	_ = store.SaveToken(context.Background(), oauth.AccessToken{
		Token:     token,
		ClientID:  ts.URL,
		Scope:     "mcp",
		ExpiresAt: time.Now().Add(-time.Hour), // already expired
	})

	srv := oauth.New(oauth.Config{
		Issuer:       ts.URL,
		VerifyBearer: func(string) bool { return true },
	}, store)

	_, err := srv.ValidateAccessToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected ErrTokenExpired, got nil")
	}
	fmt.Println("expired error:", err)
}

func TestValidateAccessToken_Unknown(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })

	srv := oauth.New(oauth.Config{
		Issuer:       ts.URL,
		VerifyBearer: func(string) bool { return true },
	}, store)

	_, err := srv.ValidateAccessToken(context.Background(), "nonexistent-token")
	if err == nil {
		t.Fatal("expected error for unknown token, got nil")
	}
}
