package oauth_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"smeldr.dev/oauth"
)

func TestRegister_Valid(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	resp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{
		"redirect_uris": ["https://client.example.com/callback"],
		"client_name": "Test Registered Client"
	}`))
	if err != nil {
		t.Fatalf("POST /oauth/register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want 201; body: %s", resp.StatusCode, body)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result) //nolint:errcheck

	clientID, _ := result["client_id"].(string)
	if !strings.HasPrefix(clientID, "dcr_") {
		t.Errorf("client_id = %q, want dcr_ prefix", clientID)
	}
	if result["client_name"] != "Test Registered Client" {
		t.Errorf("client_name = %v, want %q", result["client_name"], "Test Registered Client")
	}
	if result["token_endpoint_auth_method"] != "none" {
		t.Errorf("token_endpoint_auth_method = %v, want none", result["token_endpoint_auth_method"])
	}
	if result["client_id_issued_at"] == nil {
		t.Error("missing client_id_issued_at")
	}
	redirectURIs, _ := result["redirect_uris"].([]any)
	if len(redirectURIs) != 1 || redirectURIs[0] != "https://client.example.com/callback" {
		t.Errorf("redirect_uris = %v, want [https://client.example.com/callback]", redirectURIs)
	}
	grantTypes, _ := result["grant_types"].([]any)
	if len(grantTypes) != 1 || grantTypes[0] != "authorization_code" {
		t.Errorf("grant_types = %v, want default [authorization_code]", grantTypes)
	}
}

func TestRegister_MalformedBody(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	resp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`not json`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestRegister_MissingRedirectURIs(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	resp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name": "No URIs"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result) //nolint:errcheck
	if result["error"] != "invalid_client_metadata" {
		t.Errorf("error = %v, want invalid_client_metadata", result["error"])
	}
}

func TestRegister_UnsupportedAuthMethod(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	resp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{
		"redirect_uris": ["https://client.example.com/callback"],
		"token_endpoint_auth_method": "client_secret_basic"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestRegister_UnsupportedGrantType(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	resp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{
		"redirect_uris": ["https://client.example.com/callback"],
		"grant_types": ["client_credentials"]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestRegister_UnsupportedResponseType(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	resp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{
		"redirect_uris": ["https://client.example.com/callback"],
		"response_types": ["token"]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestRegister_OverCap(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	orig := oauth.MaxRegisteredClients
	oauth.MaxRegisteredClients = 1
	t.Cleanup(func() { oauth.MaxRegisteredClients = orig })

	body := `{"redirect_uris": ["https://client.example.com/callback"]}`

	first, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first registration: status %d, want 201", first.StatusCode)
	}

	second, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second registration: status %d, want 429", second.StatusCode)
	}
}

func TestRegister_CountRegisteredClientsFails(t *testing.T) {
	fs := newFailStore(t)
	fs.failCountRegisteredClients = true
	ts := newFailTestServer(t, fs)

	resp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(
		`{"redirect_uris": ["https://client.example.com/callback"]}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", resp.StatusCode)
	}
}

func TestRegister_SaveRegisteredClientFails(t *testing.T) {
	fs := newFailStore(t)
	fs.failSaveRegisteredClient = true
	ts := newFailTestServer(t, fs)

	resp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(
		`{"redirect_uris": ["https://client.example.com/callback"]}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", resp.StatusCode)
	}
}

// TestRegister_FullFlow proves resolveClient's DCR branch actually works
// end-to-end: register a client, then run it through the full
// authorize -> token exchange using only the client_id /oauth/register
// returned (never a CIMD URL).
func TestRegister_FullFlow(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	verifier, challenge := testPKCE()
	redirectURI := "https://dcr-client.example.com/callback"

	regResp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{
		"redirect_uris": ["`+redirectURI+`"],
		"client_name": "DCR Full Flow Client"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	defer regResp.Body.Close()
	var reg map[string]any
	json.NewDecoder(regResp.Body).Decode(&reg) //nolint:errcheck
	clientID, _ := reg["client_id"].(string)
	if clientID == "" {
		t.Fatal("registration did not return a client_id")
	}

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"bearer_token":          {"valid-forge-token"},
		"resource":              {testResource(ts)},
	}
	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	authResp, err := client.PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(authResp.Body)
		t.Fatalf("authorize status %d, want 302; body: %s", authResp.StatusCode, body)
	}
	loc, err := url.Parse(authResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect location %q has no code param", authResp.Header.Get("Location"))
	}

	tokResp := postToken(t, ts.Client(), ts.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"resource":      {testResource(ts)},
	})
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("token status %d, want 200; body: %s", tokResp.StatusCode, body)
	}
	var tok map[string]any
	json.NewDecoder(tokResp.Body).Decode(&tok) //nolint:errcheck
	if s, _ := tok["access_token"].(string); s == "" {
		t.Error("missing access_token from a DCR-registered client's code exchange")
	}
}
