package oauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"smeldr.dev/oauth"
)

func registerJSON(t *testing.T, uris []string, name string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"redirect_uris": uris, "client_name": name})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func postRegister(t *testing.T, ts *httptest.Server, body string) (int, map[string]any) {
	t.Helper()
	resp, err := ts.Client().Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out) //nolint:errcheck
	return resp.StatusCode, out
}

func TestRegister_Bounds(t *testing.T) {
	ten := make([]string, oauth.MaxRedirectURIs)
	for i := range ten {
		ten[i] = "https://client.example/cb" + strings.Repeat("x", i)
	}
	long := "https://client.example/" + strings.Repeat("a", oauth.MaxRedirectURILength-len("https://client.example/"))
	cases := []struct {
		name    string
		uris    []string
		client  string
		status  int
		errCode string
	}{
		{"https", []string{"https://client.example/cb"}, "c", 201, ""},
		{"loopback v4 with port", []string{"http://127.0.0.1:8080/cb"}, "c", 201, ""},
		{"loopback v6", []string{"http://[::1]/cb"}, "c", 201, ""},
		{"localhost", []string{"http://localhost/cb"}, "c", 201, ""},
		{"private-use scheme", []string{"com.example.app:/oauth2redirect"}, "c", 201, ""},
		{"exactly the URI cap", ten, "c", 201, ""},
		{"exactly the length cap", []string{long}, "c", 201, ""},
		{"exactly the name cap", []string{"https://client.example/cb"}, strings.Repeat("n", oauth.MaxClientNameLength), 201, ""},

		{"one URI over the cap", append(append([]string{}, ten...), "https://client.example/extra"), "c", 400, "invalid_redirect_uri"},
		{"one byte over the length cap", []string{long + "a"}, "c", 400, "invalid_redirect_uri"},
		{"relative", []string{"/relative"}, "c", 400, "invalid_redirect_uri"},
		{"fragment", []string{"https://client.example/cb#frag"}, "c", 400, "invalid_redirect_uri"},
		{"remote plain http", []string{"http://evil.example/cb"}, "c", 400, "invalid_redirect_uri"},
		{"javascript", []string{"javascript:alert(1)"}, "c", 400, "invalid_redirect_uri"},
		{"mixed-case JavaScript", []string{"JavaScript:alert(1)"}, "c", 400, "invalid_redirect_uri"},
		{"data", []string{"data:text/html,x"}, "c", 400, "invalid_redirect_uri"},
		{"vbscript", []string{"vbscript:x"}, "c", 400, "invalid_redirect_uri"},
		{"file", []string{"file:///etc/passwd"}, "c", 400, "invalid_redirect_uri"},
		{"https without host", []string{"https:///cb"}, "c", 400, "invalid_redirect_uri"},
		{"bare scheme without a dot", []string{"myapp:/cb"}, "c", 400, "invalid_redirect_uri"},
		{"unparsable", []string{"https://client.example/%zz"}, "c", 400, "invalid_redirect_uri"},
		{"name one byte over the cap", []string{"https://client.example/cb"}, strings.Repeat("n", oauth.MaxClientNameLength+1), 400, "invalid_client_metadata"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, store := newTestServer(t, func(string) bool { return true })
			status, out := postRegister(t, ts, registerJSON(t, tc.uris, tc.client))
			if status != tc.status {
				t.Fatalf("status = %d (%v), want %d", status, out, tc.status)
			}
			n, err := store.CountRegisteredClients(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if tc.status != 201 {
				if out["error"] != tc.errCode {
					t.Errorf("error = %v, want %q", out["error"], tc.errCode)
				}
				if n != 0 {
					t.Errorf("a refused registration stored %d clients", n)
				}
			} else if n != 1 {
				t.Errorf("an accepted registration stored %d clients, want 1", n)
			}
		})
	}
}

// A body over MaxRegistrationBodyBytes is refused with 413 before it is
// decoded, and nothing is stored.
func TestRegister_BodyTooLarge(t *testing.T) {
	ts, store := newTestServer(t, func(string) bool { return true })
	pad := strings.Repeat("x", int(oauth.MaxRegistrationBodyBytes))
	body := `{"redirect_uris":["https://client.example/cb"],"client_name":"` + pad + `"}`
	status, out := postRegister(t, ts, body)
	if status != http.StatusRequestEntityTooLarge || out["error"] != "invalid_client_metadata" {
		t.Errorf("status = %d, body %v; want 413 invalid_client_metadata", status, out)
	}
	if n, _ := store.CountRegisteredClients(context.Background()); n != 0 {
		t.Errorf("stored %d clients", n)
	}
}
