package oauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// failingWriter is a ResponseWriter whose body writes fail, as when the client
// has gone away.
type failingWriter struct{ h http.Header }

func (f *failingWriter) Header() http.Header       { return f.h }
func (f *failingWriter) WriteHeader(int)           {}
func (f *failingWriter) Write([]byte) (int, error) { return 0, errors.New("client gone") }

func newCoverageServer(t *testing.T) (*Server, *SQLiteStore) {
	t.Helper()
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return New(Config{
		Issuer:       "https://cms.example.com",
		Resource:     "https://cms.example.com/mcp",
		VerifyBearer: func(string) bool { return true },
	}, store), store
}

// A failed write of the authorization form is logged, and the handler returns
// without a panic.
func TestAuthorizeGet_FormWriteFailure(t *testing.T) {
	s, _ := newCoverageServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/oauth/register",
		strings.NewReader(`{"redirect_uris":["https://client.example/cb"]}`)))
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil || reg.ClientID == "" {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	q := url.Values{
		"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {"https://client.example/cb"},
		"code_challenge": {"abc"}, "code_challenge_method": {"S256"}, "resource": {"https://cms.example.com/mcp"},
	}
	w := &failingWriter{h: http.Header{}}
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if ct := w.h.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("the form was not reached: Content-Type %q", ct)
	}
}

// A CIMD document whose body breaks off mid-read is refused with "CIMD read".
func TestFetchCIMD_BodyReadFailure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"client_id"`)) //nolint:errcheck
		w.(http.Flusher).Flush()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer ts.Close()
	s, _ := newCoverageServer(t)
	s.cfg.HTTPClient = ts.Client()
	if _, err := s.fetchCIMD(ts.URL+"/client.json", "https://client.example/cb"); err == nil || !strings.Contains(err.Error(), "CIMD read") {
		t.Errorf("err = %v, want a CIMD read error", err)
	}
}

// A database error (not a missing row) is returned as it is.
func TestSQLiteStore_GetErrorsOnClosedStore(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	ctx := context.Background()
	if _, err := store.GetRefreshToken(ctx, "x"); err == nil || errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("GetRefreshToken on a closed store = %v, want a database error", err)
	}
	if _, err := store.GetRegisteredClient(ctx, "x"); err == nil || errors.Is(err, ErrRegisteredClientNotFound) {
		t.Errorf("GetRegisteredClient on a closed store = %v, want a database error", err)
	}
}

// A stored client whose redirect_uris is not JSON is refused on read.
func TestSQLiteStore_GetRegisteredClientCorruptRow(t *testing.T) {
	_, store := newCoverageServer(t)
	if _, err := store.db.Exec(`INSERT INTO smeldr_oauth_registered_clients (client_id, client_name, redirect_uris, created_at)
		VALUES ('dcr_bad', 'bad', 'not json', 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetRegisteredClient(context.Background(), "dcr_bad"); err == nil || !strings.Contains(err.Error(), "unmarshal redirect_uris") {
		t.Errorf("err = %v, want an unmarshal error", err)
	}
}

// seedReadOnly creates a file database with the given schema, closes it, and
// returns a read-only DSN for it.
func seedReadOnly(t *testing.T, schema string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return "file:" + filepath.ToSlash(path) + "?mode=ro"
}

// A legacy forge_oauth_* table that cannot be renamed (the file is read-only)
// makes NewSQLiteStore refuse with "migrate tables".
func TestNewSQLiteStore_LegacyRenameFails(t *testing.T) {
	dsn := seedReadOnly(t, `CREATE TABLE forge_oauth_codes (code TEXT PRIMARY KEY)`)
	store, err := NewSQLiteStore(dsn)
	if err == nil {
		store.Close()
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "migrate tables") {
		t.Errorf("err = %v, want migrate tables", err)
	}
}

// An old smeldr_oauth_codes without the resource column, on a read-only file,
// makes NewSQLiteStore refuse with "migrate resource column".
func TestNewSQLiteStore_ResourceColumnFails(t *testing.T) {
	dsn := seedReadOnly(t, `CREATE TABLE smeldr_oauth_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL,
		redirect_uri TEXT NOT NULL, scope TEXT NOT NULL, code_challenge TEXT NOT NULL, expires_at INTEGER NOT NULL)`)
	store, err := NewSQLiteStore(dsn)
	if err == nil {
		store.Close()
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "migrate resource column") {
		t.Errorf("err = %v, want migrate resource column", err)
	}
}
