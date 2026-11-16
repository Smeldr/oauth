package oauth

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// core T1286: the issuer is checked where it is defined.
func TestValidateIssuer(t *testing.T) {
	for _, c := range []struct {
		issuer string
		want   string // empty: valid
	}{
		{"https://cms.example.com", ""},
		{"https://cms.example.com:8443/auth", ""},
		{"http://localhost:8080", ""},
		{"http://127.0.0.1:9000", ""},
		{"http://[::1]:9000", ""},
		{"http://192.168.1.10:8080", ""}, // allowed, with a warning at New
		{"http://nas.local", ""},
		{"", "is not an absolute URL with a host"},
		{"not-a-url", "is not an absolute URL with a host"},
		{"/oauth", "is not an absolute URL with a host"},
		{"https://", "is not an absolute URL with a host"},
		{"https://:443", "is not an absolute URL with a host"},
		{"ftp://cms.example.com", `must use https or http, not "ftp"`},
		{"https://user:pw@cms.example.com", ""}, // allowed, with a warning at New
		{"https://cms.example.com?x=1", "must not have a query"},
		{"https://cms.example.com?", "must not have a query"},
		{"https://cms.example.com#top", "must not have a fragment"},
		{"https://cms.example.com/", ""}, // allowed, with a warning at New
		{"https://cms.example.com/auth/", ""},
		{"https://user:secret@cms.example.com?x=1", "must not have a query"},
	} {
		err := ValidateIssuer(c.issuer)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%q: %v, want valid", c.issuer, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "Config.Issuer")):
			t.Errorf("%q: %v, want %q", c.issuer, err, c.want)
		case err != nil && strings.Contains(err.Error(), "secret"):
			t.Errorf("%q: the error shows the password: %v", c.issuer, err)
		}
	}
}

// New panics with ValidateIssuer's message for an issuer it refuses.
func TestNew_RefusesAnInvalidIssuer(t *testing.T) {
	defer func() {
		r := recover()
		if s, _ := r.(string); !strings.Contains(s, `Config.Issuer "not-a-url" is not an absolute URL with a host`) {
			t.Errorf("panic %v, want the issuer message", r)
		}
	}()
	New(Config{Issuer: "not-a-url", Resource: "https://cms.example.com/mcp", VerifyBearer: func(string) bool { return true }}, nil)
}

// Each form that works but should not starts with one warning of its own;
// https and loopback http log none, and a password never reaches the log.
func TestNew_WarnsOncePerIssuerFault(t *testing.T) {
	resolve := func(string) (Subject, bool) { return Subject{}, false }
	active := func(string) (Subject, bool) { return Subject{}, false }
	for _, c := range []struct {
		issuer string
		want   []string
	}{
		{"https://cms.example.com", nil},
		{"http://localhost:8080", nil},
		{"http://192.168.1.10:8080", []string{"travel in the clear"}},
		{"https://user:secret@cms.example.com", []string{"carries user info"}},
		{"https://cms.example.com/", []string{"ends with a slash"}},
		{"http://user:secret@nas.local/", []string{"travel in the clear", "carries user info", "ends with a slash"}},
	} {
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		New(Config{Issuer: c.issuer, Resource: "https://cms.example.com/mcp", ResolveBearer: resolve, TokenActive: active}, nil)
		slog.SetDefault(prev)
		out := buf.String()
		if n := strings.Count(out, "level=WARN"); n != len(c.want) {
			t.Errorf("%q: %d warnings, want %d: %s", c.issuer, n, len(c.want), out)
		}
		for _, w := range c.want {
			if strings.Count(out, w) != 1 {
				t.Errorf("%q: want one %q: %s", c.issuer, w, out)
			}
		}
		if strings.Contains(out, "secret") {
			t.Errorf("%q: the log shows the password: %s", c.issuer, out)
		}
	}
}
