package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCanonicalClientID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare URL unchanged", "https://client.example.com/app", "https://client.example.com/app"},
		{"strips query", "https://client.example.com/app?token_endpoint_auth_method=none", "https://client.example.com/app"},
		{"strips fragment", "https://client.example.com/app#section", "https://client.example.com/app"},
		{"strips query and fragment", "https://client.example.com/app?a=1&b=2#frag", "https://client.example.com/app"},
		{"invalid URL falls back unchanged", "https://a b c", "https://a b c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canonicalClientID(tt.in); got != tt.want {
				t.Errorf("canonicalClientID(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func testFetchServer(t *testing.T, ts *httptest.Server) *Server {
	t.Helper()
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return New(Config{
		Issuer:       ts.URL,
		Resource:     ts.URL + "/mcp",
		VerifyBearer: func(string) bool { return true },
		HTTPClient:   ts.Client(),
	}, store)
}

func TestFetchCIMD_ClientIDQuerySuffix_Accepted(t *testing.T) {
	// ChatGPT's Reconnect flow: the requested client_id carries a
	// ?token_endpoint_auth_method=none suffix the CIMD doc itself doesn't echo.
	ts := httptest.NewTLSServer(nil)
	defer ts.Close()
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"client_id":     ts.URL, // doc declares the bare URL, no suffix
			"client_name":   "ChatGPT",
			"redirect_uris": []string{ts.URL + "/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc) //nolint:errcheck
	})
	srv := testFetchServer(t, ts)

	requested := ts.URL + "?token_endpoint_auth_method=none"
	doc, err := srv.fetchCIMD(requested, ts.URL+"/callback")
	if err != nil {
		t.Fatalf("fetchCIMD: %v", err)
	}
	if doc.ClientName != "ChatGPT" {
		t.Errorf("ClientName = %q, want ChatGPT", doc.ClientName)
	}
}

func TestFetchCIMD_ClientIDDifferentPath_Rejected(t *testing.T) {
	ts := httptest.NewTLSServer(nil)
	defer ts.Close()
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"client_id":     ts.URL + "/different-path",
			"redirect_uris": []string{ts.URL + "/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc) //nolint:errcheck
	})
	srv := testFetchServer(t, ts)

	if _, err := srv.fetchCIMD(ts.URL, ts.URL+"/callback"); err == nil {
		t.Fatal("expected error for mismatched path, got nil")
	}
}

func TestFetchCIMD_ClientIDDifferentHost_Rejected(t *testing.T) {
	ts := httptest.NewTLSServer(nil)
	defer ts.Close()
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"client_id":     "https://not-this-host.example.com",
			"redirect_uris": []string{ts.URL + "/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc) //nolint:errcheck
	})
	srv := testFetchServer(t, ts)

	if _, err := srv.fetchCIMD(ts.URL, ts.URL+"/callback"); err == nil {
		t.Fatal("expected error for mismatched host, got nil")
	}
}

func TestFetchCIMD_NonHTTPS_Rejected(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	srv := New(Config{
		Issuer:       "https://issuer.example.com",
		Resource:     "https://issuer.example.com/mcp",
		VerifyBearer: func(string) bool { return true },
	}, store)

	if _, err := srv.fetchCIMD("http://client.example.com", "http://client.example.com/callback"); err == nil {
		t.Fatal("expected error for non-HTTPS client_id, got nil")
	}
}

func TestFetchCIMD_NonOKStatus_Rejected(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()
	srv := testFetchServer(t, ts)

	if _, err := srv.fetchCIMD(ts.URL, ts.URL+"/callback"); err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
}

func TestFetchCIMD_InvalidJSON_Rejected(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json")) //nolint:errcheck
	}))
	defer ts.Close()
	srv := testFetchServer(t, ts)

	if _, err := srv.fetchCIMD(ts.URL, ts.URL+"/callback"); err == nil {
		t.Fatal("expected error for invalid JSON body, got nil")
	}
}

func TestFetchCIMD_RedirectURINotListed_Rejected(t *testing.T) {
	ts := httptest.NewTLSServer(nil)
	defer ts.Close()
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"client_id":     ts.URL,
			"redirect_uris": []string{ts.URL + "/other-callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc) //nolint:errcheck
	})
	srv := testFetchServer(t, ts)

	if _, err := srv.fetchCIMD(ts.URL, ts.URL+"/callback"); err == nil {
		t.Fatal("expected error for unlisted redirect_uri, got nil")
	}
}
