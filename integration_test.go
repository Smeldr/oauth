package oauth_test

// Lag 2 — full OAuth flow integration test.
//
// One httptest.Server serves both the CIMD metadata document and all OAuth
// endpoints. The test walks the complete authorization code flow end-to-end:
//
//  1. Build PKCE pair
//  2. GET /oauth/authorize → confirm 200 HTML form
//  3. POST /oauth/authorize with valid bearer_token → follow 302 redirect
//  4. Extract code from redirect URL
//  5. POST /oauth/token with code + code_verifier → 200 JSON with access_token
//  6. ValidateAccessToken → success
//  7. Use expired code → 400

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"smeldr.dev/oauth"
)

func TestFullFlow(t *testing.T) {
	store, err := oauth.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// We need the server URL for CIMD — set up a two-phase init.
	// Use TLS server so ts.URL is https://, satisfying the CIMD HTTPS requirement.
	var ts *httptest.Server
	var oauthHandler http.Handler

	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			doc := map[string]any{
				"client_id":     ts.URL,
				"client_name":   "Integration Test Client",
				"redirect_uris": []string{ts.URL + "/callback"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(doc) //nolint:errcheck
			return
		}
		// Serve redirect target so follow-redirect works.
		if r.URL.Path == "/callback" {
			w.WriteHeader(http.StatusOK)
			return
		}
		oauthHandler.ServeHTTP(w, r)
	}))
	defer ts.Close()

	srv := oauth.New(oauth.Config{
		Issuer:       ts.URL,
		Resource:     ts.URL + "/mcp",
		VerifyBearer: func(token string) bool { return token == "valid-forge-token" },
		HTTPClient:   ts.Client(), // trusts the test TLS certificate
	}, store)
	oauthHandler = srv.Handler()

	// 1. Build PKCE pair.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// 2. GET /oauth/authorize → HTML form.
	resource := ts.URL + "/mcp"
	authParams := url.Values{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/callback"},
		"scope":                 {"mcp offline_access"},
		"state":                 {"state-xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {resource},
	}
	getResp, err := ts.Client().Get(ts.URL + "/oauth/authorize?" + authParams.Encode())
	if err != nil {
		t.Fatalf("GET /oauth/authorize: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getResp.Body)
		t.Fatalf("GET authorize: status %d; body: %s", getResp.StatusCode, body)
	}
	body, _ := io.ReadAll(getResp.Body)
	if !strings.Contains(string(body), "<form") {
		t.Fatal("GET authorize: expected HTML form")
	}

	// 3. POST /oauth/authorize with valid bearer.
	formData := url.Values{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/callback"},
		"scope":                 {"mcp offline_access"},
		"state":                 {"state-xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"bearer_token":          {"valid-forge-token"},
		"resource":              {resource},
	}
	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // don't follow; capture Location header
	}
	postResp, err := client.PostForm(ts.URL+"/oauth/authorize", formData)
	if err != nil {
		t.Fatalf("POST /oauth/authorize: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(postResp.Body)
		t.Fatalf("POST authorize: status %d; body: %s", postResp.StatusCode, body)
	}

	// 4. Extract code from redirect Location.
	location := postResp.Header.Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location %q: %v", location, err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in Location: %q", location)
	}
	if parsed.Query().Get("state") != "state-xyz" {
		t.Errorf("state mismatch in Location: %q", location)
	}
	if parsed.Query().Get("iss") != ts.URL {
		t.Errorf("iss = %q in Location, want %q (RFC 9207)", parsed.Query().Get("iss"), ts.URL)
	}

	// 5. POST /oauth/token — code exchange.
	tokenResp, err := ts.Client().PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {ts.URL},
		"redirect_uri":  {ts.URL + "/callback"},
		"code_verifier": {verifier},
		"resource":      {resource},
	})
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token exchange: status %d; body: %s", tokenResp.StatusCode, body)
	}
	var tokenResult map[string]any
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenResult); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	accessToken, _ := tokenResult["access_token"].(string)
	if accessToken == "" {
		t.Fatal("no access_token in response")
	}
	refreshToken, _ := tokenResult["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("no refresh_token in response (offline_access scope was present)")
	}

	// 6. ValidateAccessToken → success.
	at, err := srv.ValidateAccessToken(context.Background(), accessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if at.Scope != "mcp offline_access" {
		t.Errorf("scope = %q, want %q", at.Scope, "mcp offline_access")
	}
	if at.Resource != resource {
		t.Errorf("Resource = %q, want %q", at.Resource, resource)
	}

	// 7. Use the same (now deleted) code again → 400 invalid_grant.
	expiredResp, err := ts.Client().PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {ts.URL},
		"redirect_uri":  {ts.URL + "/callback"},
		"code_verifier": {verifier},
		"resource":      {resource},
	})
	if err != nil {
		t.Fatalf("POST /oauth/token (replay): %v", err)
	}
	defer expiredResp.Body.Close()
	if expiredResp.StatusCode != http.StatusBadRequest {
		t.Errorf("replay: status %d, want 400", expiredResp.StatusCode)
	}
}

func TestFullFlow_RefreshToken(t *testing.T) {
	store, err := oauth.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	srv := oauth.New(oauth.Config{
		Issuer:       "https://example.com",
		Resource:     "https://example.com/mcp",
		VerifyBearer: func(string) bool { return true },
	}, store)

	// Pre-store a refresh token.
	refreshToken := "integration-refresh-token-001"
	_ = store.SaveRefreshToken(context.Background(), oauth.RefreshToken{
		Token:    refreshToken,
		ClientID: "https://client.example.com",
		Scope:    "mcp offline_access",
	})

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := ts.Client().PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"https://client.example.com"},
	})
	if err != nil {
		t.Fatalf("POST /oauth/token (refresh): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("refresh: status %d; body: %s", resp.StatusCode, body)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["access_token"] == "" {
		t.Error("missing access_token in refresh response")
	}

	// Validate the new access token.
	at, err := srv.ValidateAccessToken(context.Background(), result["access_token"].(string))
	if err != nil {
		t.Fatalf("ValidateAccessToken after refresh: %v", err)
	}
	if at.ExpiresAt.Before(time.Now()) {
		t.Error("issued access token is already expired")
	}
}
