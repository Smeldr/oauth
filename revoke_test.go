package oauth_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"smeldr.dev/oauth"
)

func TestRevoke_DeletesRefreshToken(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })

	tok := "revoke-test-token"
	if err := store.SaveRefreshToken(context.Background(), oauth.RefreshToken{
		Token:    tok,
		ClientID: ts.URL,
		Scope:    "mcp offline_access",
	}); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	resp, err := ts.Client().PostForm(ts.URL+"/oauth/revoke", url.Values{"token": {tok}})
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200", resp.StatusCode)
	}

	if _, err := store.GetRefreshToken(context.Background(), tok); err != oauth.ErrRefreshTokenNotFound {
		t.Errorf("GetRefreshToken after revoke: err = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestRevoke_UnknownToken_StillOK(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	resp, err := ts.Client().PostForm(ts.URL+"/oauth/revoke", url.Values{"token": {"never-issued"}})
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200 per RFC 7009 (unknown token must still be OK)", resp.StatusCode)
	}
}

func TestRevoke_TokenTypeHintIgnored(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })

	tok := "revoke-test-token-hint"
	if err := store.SaveRefreshToken(context.Background(), oauth.RefreshToken{
		Token:    tok,
		ClientID: ts.URL,
		Scope:    "mcp",
	}); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	resp, err := ts.Client().PostForm(ts.URL+"/oauth/revoke", url.Values{
		"token":           {tok},
		"token_type_hint": {"access_token"}, // accepted but not enforced, per RFC 7009 §2.1
	})
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200", resp.StatusCode)
	}
}

func TestRevoke_MalformedBody_StillOK(t *testing.T) {
	ts, _ := newTestServer(t, func(string) bool { return true })

	// Invalid percent-encoding makes r.ParseForm() fail — must still
	// return 200 per RFC 7009.
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/oauth/revoke", strings.NewReader("token=%zz"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200 even on malformed body", resp.StatusCode)
	}
}
