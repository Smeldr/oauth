package oauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"smeldr.dev/oauth"
)

// memStore is a minimal in-memory [oauth.Store] that deliberately does NOT
// implement [oauth.RegistrationStore] — used to prove that a Store without
// Dynamic Client Registration support behaves exactly as it did before this
// feature existed (the CIMD path is unaffected, and DCR surfaces are simply
// absent rather than broken).
type memStore struct {
	mu     sync.Mutex
	codes  map[string]oauth.AuthCode
	tokens map[string]oauth.AccessToken
}

func newMemStore() *memStore {
	return &memStore{codes: map[string]oauth.AuthCode{}, tokens: map[string]oauth.AccessToken{}}
}

func (m *memStore) SaveCode(_ context.Context, c oauth.AuthCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[c.Code] = c
	return nil
}

func (m *memStore) GetCode(_ context.Context, code string) (oauth.AuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[code]
	if !ok {
		return oauth.AuthCode{}, oauth.ErrCodeNotFound
	}
	return c, nil
}

func (m *memStore) DeleteCode(_ context.Context, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.codes, code)
	return nil
}

func (m *memStore) SaveToken(_ context.Context, t oauth.AccessToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.Token] = t
	return nil
}

func (m *memStore) GetToken(_ context.Context, token string) (oauth.AccessToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[token]
	if !ok {
		return oauth.AccessToken{}, oauth.ErrTokenNotFound
	}
	return t, nil
}

func (m *memStore) SaveRefreshToken(_ context.Context, _ oauth.RefreshToken) error { return nil }

func (m *memStore) GetRefreshToken(_ context.Context, _ string) (oauth.RefreshToken, error) {
	return oauth.RefreshToken{}, oauth.ErrRefreshTokenNotFound
}

func (m *memStore) DeleteRefreshToken(_ context.Context, _ string) error { return nil }

// newTestServerNoRegistration mirrors newTestServer but is backed by
// memStore, which does not implement RegistrationStore.
func newTestServerNoRegistration(t *testing.T) *httptest.Server {
	t.Helper()
	store := newMemStore()

	var ts *httptest.Server
	var oauthHandler http.Handler
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			doc := map[string]any{
				"client_id":     ts.URL,
				"client_name":   "No-Registration Test Client",
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
	}, store)
	oauthHandler = srv.Handler()
	return ts
}

func TestResolveClient_CIMDPath_UnaffectedByStoreWithoutRegistration(t *testing.T) {
	ts := newTestServerNoRegistration(t)
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
		t.Errorf("status %d, want 200 — CIMD path must work regardless of RegistrationStore support", resp.StatusCode)
	}
}

func TestResolveClient_NonURLClientID_NoRegistrationSupport_Rejected(t *testing.T) {
	ts := newTestServerNoRegistration(t)
	_, challenge := testPKCE()

	v := url.Values{
		"response_type":         {"code"},
		"client_id":             {"dcr_whatever"},
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
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400 — a non-URL client_id with no RegistrationStore backing must be rejected", resp.StatusCode)
	}
}

func TestRegisterRoute_NotMounted_WithoutRegistrationSupport(t *testing.T) {
	ts := newTestServerNoRegistration(t)

	resp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404 — /oauth/register must not be mounted for a Store without RegistrationStore support", resp.StatusCode)
	}
}

func TestResolveClient_UnknownRegisteredClientID_Rejected(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()

	v := url.Values{
		"response_type":         {"code"},
		"client_id":             {"dcr_never_registered"},
		"redirect_uri":          {"https://client.example.com/callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {testResource(ts)},
	}
	resp, err := ts.Client().Get(ts.URL + "/oauth/authorize?" + v.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400 — an unregistered dcr_ client_id must be rejected", resp.StatusCode)
	}
}

func TestResolveClient_RegisteredClient_WrongRedirectURI_Rejected(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })
	_, challenge := testPKCE()

	regResp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(
		`{"redirect_uris": ["https://client.example.com/callback"]}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	defer regResp.Body.Close()
	var reg map[string]any
	json.NewDecoder(regResp.Body).Decode(&reg) //nolint:errcheck
	clientID, _ := reg["client_id"].(string)

	v := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://client.example.com/a-different-callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {testResource(ts)},
	}
	resp, err := ts.Client().Get(ts.URL + "/oauth/authorize?" + v.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400 — a redirect_uri outside the registered set must be rejected", resp.StatusCode)
	}
}

func TestDiscovery_NoRegistrationEndpoint_WithoutRegistrationSupport(t *testing.T) {
	ts := newTestServerNoRegistration(t)

	resp, err := ts.Client().Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var meta map[string]any
	json.NewDecoder(resp.Body).Decode(&meta) //nolint:errcheck
	if _, present := meta["registration_endpoint"]; present {
		t.Error("registration_endpoint must be absent when the store doesn't support registration")
	}
}
