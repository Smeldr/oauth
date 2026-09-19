package oauth_test

import (
	"context"
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

// — parseAuthorizeParams validation branches (via the GET handler) —

func TestAuthorizeGet_ValidationBranches(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()

	base := func() url.Values {
		return url.Values{
			"response_type":         {"code"},
			"client_id":             {ts.URL},
			"redirect_uri":          {ts.URL + "/callback"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"resource":              {testResource(ts)},
		}
	}

	tests := []struct {
		name   string
		mutate func(url.Values)
		want   string
	}{
		{"wrong response_type", func(v url.Values) { v.Set("response_type", "token") }, "unsupported response_type"},
		{"missing client_id", func(v url.Values) { v.Del("client_id") }, "missing client_id"},
		{"missing redirect_uri", func(v url.Values) { v.Del("redirect_uri") }, "missing redirect_uri"},
		{"missing code_challenge", func(v url.Values) { v.Del("code_challenge") }, "missing code_challenge"},
		{"wrong code_challenge_method", func(v url.Values) { v.Set("code_challenge_method", "plain") }, "unsupported code_challenge_method"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := base()
			tt.mutate(v)
			resp, err := ts.Client().Get(ts.URL + "/oauth/authorize?" + v.Encode())
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status %d, want 400", resp.StatusCode)
			}
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), tt.want) {
				t.Errorf("body = %q, want it to contain %q", body, tt.want)
			}
		})
	}
}

// newTestServerNoClientName mirrors newTestServer but serves a CIMD document
// with no client_name — exercising the "fall back to displaying the raw
// client_id" branch in both the GET and POST authorize handlers.
func newTestServerNoClientName(t *testing.T, verifyBearer func(string) bool) *httptest.Server {
	t.Helper()
	store, err := oauth.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	var ts *httptest.Server
	var oauthHandler http.Handler
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			doc := map[string]any{
				"client_id":     ts.URL,
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
		VerifyBearer: verifyBearer,
		HTTPClient:   ts.Client(),
	}, store)
	oauthHandler = srv.Handler()
	return ts
}

func TestAuthorizeGet_NoClientName_FallsBackToClientID(t *testing.T) {
	ts := newTestServerNoClientName(t, func(string) bool { return true })
	_, challenge := testPKCE()

	v := url.Values{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {ts.URL + "/mcp"},
	}
	resp, err := ts.Client().Get(ts.URL + "/oauth/authorize?" + v.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), ts.URL) {
		t.Error("expected form to fall back to client_id as the displayed name")
	}
}

func TestAuthorizePost_NoClientName_InvalidBearer_FallsBackToClientID(t *testing.T) {
	ts := newTestServerNoClientName(t, func(string) bool { return false })
	_, challenge := testPKCE()

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"bearer_token":          {"bad-token"},
		"resource":              {ts.URL + "/mcp"},
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
	if !strings.Contains(string(body), ts.URL) {
		t.Error("expected re-rendered form to fall back to client_id as the displayed name")
	}
}

// — authorizePostHandler branches not covered by TestAuthorizePost_* —

func TestAuthorizePost_ParseFormFailure(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	// Invalid percent-encoding in an urlencoded body makes url.ParseQuery
	// (called from r.ParseForm) return an error.
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/oauth/authorize", strings.NewReader("a=%zz"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizePost_ValidationFailure(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"bearer_token":          {"valid-forge-token"},
		// resource omitted — parseAuthorizeParams rejects this
	}
	resp, err := ts.Client().PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizePost_CIMDFetchFailure(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {"https://unreachable.forge-test.invalid"},
		"redirect_uri":          {"https://unreachable.forge-test.invalid/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"bearer_token":          {"valid-forge-token"},
		"resource":              {testResource(ts)},
	}
	resp, err := ts.Client().PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

// — tokenHandler branches —

func TestTokenHandler_UnsupportedGrantType(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	resp := postToken(t, ts.Client(), ts.URL, url.Values{"grant_type": {"client_credentials"}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["error"] != "unsupported_grant_type" {
		t.Errorf("error = %q, want unsupported_grant_type", result["error"])
	}
}

func TestTokenHandler_ParseFormFailure(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader("a=%zz"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

// — handleCodeExchange branches —

func TestTokenExchange_MissingParam(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	verifier, _ := testPKCE()

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type": {"authorization_code"},
		// code omitted
		"client_id":     {ts.URL},
		"redirect_uri":  {ts.URL + "/callback"},
		"code_verifier": {verifier},
		"resource":      {testResource(ts)},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", result["error"])
	}
}

func TestTokenExchange_CodeNotFound(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	verifier, _ := testPKCE()

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"never-issued"},
		"client_id":     {ts.URL},
		"redirect_uri":  {ts.URL + "/callback"},
		"code_verifier": {verifier},
		"resource":      {testResource(ts)},
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

func TestTokenExchange_ClientIDMismatch(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })
	verifier, challenge := testPKCE()

	code := "test-code-client-mismatch"
	_ = store.SaveCode(context.Background(), oauth.AuthCode{
		Code:          code,
		ClientID:      ts.URL,
		RedirectURI:   ts.URL + "/callback",
		Scope:         "mcp",
		CodeChallenge: challenge,
		Resource:      testResource(ts),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"https://different-client.example.com"},
		"redirect_uri":  {ts.URL + "/callback"},
		"code_verifier": {verifier},
		"resource":      {testResource(ts)},
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

func TestTokenExchange_RedirectURIMismatch(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })
	verifier, challenge := testPKCE()

	code := "test-code-redirect-mismatch"
	_ = store.SaveCode(context.Background(), oauth.AuthCode{
		Code:          code,
		ClientID:      ts.URL,
		RedirectURI:   ts.URL + "/callback",
		Scope:         "mcp",
		CodeChallenge: challenge,
		Resource:      testResource(ts),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {ts.URL},
		"redirect_uri":  {ts.URL + "/different-callback"},
		"code_verifier": {verifier},
		"resource":      {testResource(ts)},
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

// — handleRefreshToken branches —

func TestTokenRefresh_MissingParam(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type": {"refresh_token"},
		// refresh_token omitted
		"client_id": {ts.URL},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", result["error"])
	}
}

func TestTokenRefresh_ClientIDMismatch(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })

	refreshToken := "test-refresh-client-mismatch"
	_ = store.SaveRefreshToken(context.Background(), oauth.RefreshToken{
		Token:    refreshToken,
		ClientID: ts.URL,
		Scope:    "mcp offline_access",
	})

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"https://different-client.example.com"},
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

// — containsScope edge cases (indirectly, via whether a refresh_token is
// issued at code exchange — containsScope is unexported) —

func TestTokenExchange_NoOfflineAccess_NoRefreshToken(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })
	verifier, challenge := testPKCE()

	code := "test-code-no-offline-access"
	_ = store.SaveCode(context.Background(), oauth.AuthCode{
		Code:          code,
		ClientID:      ts.URL,
		RedirectURI:   ts.URL + "/callback",
		Scope:         "mcp", // no offline_access
		CodeChallenge: challenge,
		Resource:      testResource(ts),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	resp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {ts.URL},
		"redirect_uri":  {ts.URL + "/callback"},
		"code_verifier": {verifier},
		"resource":      {testResource(ts)},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if _, present := result["refresh_token"]; present {
		t.Error("did not expect refresh_token without offline_access scope")
	}
}

// — server.go —

func TestNew_PanicsOnEmptyIssuer(t *testing.T) {
	store := testStore(t)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty Config.Issuer, got none")
		}
	}()
	oauth.New(oauth.Config{
		Resource:     "https://server.example.com/mcp",
		VerifyBearer: func(string) bool { return true },
	}, store)
}

func TestNew_PanicsOnNilVerifyBearer(t *testing.T) {
	store := testStore(t)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil Config.VerifyBearer, got none")
		}
	}()
	oauth.New(oauth.Config{
		Issuer:   "https://cms.example.com",
		Resource: "https://cms.example.com/mcp",
	}, store)
}

func TestNew_DefaultsHTTPClient(t *testing.T) {
	store := testStore(t)
	// HTTPClient omitted — New must default it rather than leaving it nil
	// (a nil client would panic the first time a CIMD fetch happens).
	srv := oauth.New(oauth.Config{
		Issuer:       "https://cms.example.com",
		Resource:     "https://cms.example.com/mcp",
		VerifyBearer: func(string) bool { return true },
	}, store)
	if srv == nil {
		t.Fatal("New returned nil")
	}
}

func TestIssuer(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	store := testStore(t)
	srv := oauth.New(oauth.Config{
		Issuer:       ts.URL,
		Resource:     ts.URL + "/mcp",
		VerifyBearer: func(string) bool { return true },
	}, store)
	if got := srv.Issuer(); got != ts.URL {
		t.Errorf("Issuer() = %q, want %q", got, ts.URL)
	}
}
