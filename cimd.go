package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// CIMDDoc is the parsed client identity metadata document (CIMD).
// The server fetches this document from the client_id URL on every
// authorization request — no client registration database required.
type CIMDDoc struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// fetchCIMD retrieves and validates the CIMD document at clientID.
//
// Validation steps:
//  1. clientID must be a valid HTTPS URL (HTTP and non-URLs are rejected)
//  2. GET clientID with the configured HTTP client (5 s default timeout)
//  3. Response body is read and parsed as JSON into [CIMDDoc]
//  4. doc.ClientID must equal the clientID parameter
//  5. redirectURI must appear in doc.RedirectURIs
//
// On any failure an error is returned and the caller must log a Warn event.
func (s *Server) fetchCIMD(clientID, redirectURI string) (*CIMDDoc, error) {
	if !strings.HasPrefix(clientID, "https://") {
		return nil, fmt.Errorf("oauth: client_id must be an HTTPS URL, got %q", clientID)
	}

	resp, err := s.cfg.HTTPClient.Get(clientID) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("oauth: CIMD fetch %q: %w", clientID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth: CIMD fetch %q: status %d", clientID, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("oauth: CIMD read %q: %w", clientID, err)
	}

	var doc CIMDDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oauth: CIMD parse %q: %w", clientID, err)
	}

	if canonicalClientID(doc.ClientID) != canonicalClientID(clientID) {
		return nil, fmt.Errorf("oauth: CIMD client_id mismatch: got %q, want %q", doc.ClientID, clientID)
	}

	for _, u := range doc.RedirectURIs {
		if u == redirectURI {
			return &doc, nil
		}
	}
	return nil, fmt.Errorf("oauth: redirect_uri %q not listed in CIMD for %q", redirectURI, clientID)
}

// canonicalClientID strips the query string and fragment from a client_id
// URL for CIMD self-declaration comparison. A client may append query
// parameters (e.g. ChatGPT's own token_endpoint_auth_method=none) to its
// client_id without those parameters being part of the document's declared
// identity — only fetchCIMD's own doc.ClientID equality check is relaxed
// this way; the literal client_id string (query included) is still what
// gets fetched, stored, and compared at token exchange.
func canonicalClientID(clientID string) string {
	u, err := url.Parse(clientID)
	if err != nil {
		return clientID
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
