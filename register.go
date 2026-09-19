package oauth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// MaxRegisteredClients bounds how many Dynamic Client Registration records
// SaveRegisteredClient will accept before rejecting new registrations — an
// unauthenticated POST /oauth/register has no other resource-exhaustion
// guard, unlike every other stateful record in this store (which all carry
// ExpiresAt; RegisteredClient does not, by RFC 7591's own permanent-
// registration model, so a count ceiling substitutes for a TTL here).
var MaxRegisteredClients = 10000

// RegisteredClient is a client registered via Dynamic Client Registration
// (RFC 7591). Unlike CIMD, its identity is opaque (server-issued), not a
// fetchable URL.
type RegisteredClient struct {
	// ClientID is the server-generated, opaque identifier ("dcr_" + 32 hex
	// chars), never an HTTPS URL — that prefix is how [Server.resolveClient]
	// tells a registered client apart from a CIMD client_id.
	ClientID string
	// ClientName is the human-readable name supplied at registration, shown
	// on the authorization form in place of the raw client_id.
	ClientName string
	// RedirectURIs is the set of callback URLs this client registered.
	// A /oauth/authorize request must use one of these exactly.
	RedirectURIs []string
	// CreatedAt is when this client was registered.
	CreatedAt time.Time
}

// RegistrationStore is implemented by a [Store] that also supports Dynamic
// Client Registration (RFC 7591). [SQLiteStore] implements it. POST
// /oauth/register — and the registration_endpoint metadata field — are
// only mounted when the configured Store satisfies this interface, so a
// custom Store implementation that predates this feature keeps compiling
// unchanged and simply doesn't expose registration.
type RegistrationStore interface {
	// SaveRegisteredClient persists a newly registered client.
	SaveRegisteredClient(ctx context.Context, c RegisteredClient) error
	// GetRegisteredClient retrieves a registered client by its client_id.
	// Returns [ErrRegisteredClientNotFound] if the client_id does not exist.
	GetRegisteredClient(ctx context.Context, clientID string) (RegisteredClient, error)
	// CountRegisteredClients returns the total number of registered
	// clients, used to enforce [MaxRegisteredClients] at registration time.
	CountRegisteredClients(ctx context.Context) (int, error)
}

// registerRequest is the minimal RFC 7591 §2 client metadata this server
// accepts. Only public clients are supported (this server's
// token_endpoint_auth_methods_supported is "none" only — see metadata.go),
// so token_endpoint_auth_method, if present, must be "none".
type registerRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
}

// registerResponse is the RFC 7591 §3.2.1 client information response.
type registerResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

var defaultGrantTypes = []string{"authorization_code"}
var defaultResponseTypes = []string{"code"}

// registerHandler handles POST /oauth/register per RFC 7591. Only mounted
// when the configured Store implements [RegistrationStore].
func (s *Server) registerHandler(w http.ResponseWriter, r *http.Request) {
	// Handler() only mounts this route when s.store implements
	// RegistrationStore, so this assertion cannot fail in practice — an
	// unchecked assertion here, not a defensive check, matches that
	// guarantee rather than re-testing it.
	rs := s.store.(RegistrationStore)

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "malformed JSON body")
		return
	}

	if len(req.RedirectURIs) == 0 {
		writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required and must be non-empty")
		return
	}
	if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
		writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "token_endpoint_auth_method must be \"none\" — this server does not support confidential clients")
		return
	}
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = defaultGrantTypes
	}
	for _, g := range grantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant_types value: "+g)
			return
		}
	}
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = defaultResponseTypes
	}
	if len(responseTypes) != 1 || responseTypes[0] != "code" {
		writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", `response_types must be ["code"]`)
		return
	}

	count, err := rs.CountRegisteredClients(r.Context())
	if err != nil {
		slog.Warn("oauth: register: failed to count existing clients", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if count >= MaxRegisteredClients {
		writeRegisterError(w, http.StatusTooManyRequests, "invalid_client_metadata", "registration limit reached")
		return
	}

	clientID, err := newToken(16)
	if err != nil {
		slog.Warn("oauth: register: failed to generate client_id", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	clientID = "dcr_" + clientID

	rc := RegisteredClient{
		ClientID:     clientID,
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    s.now(),
	}
	if err := rs.SaveRegisteredClient(r.Context(), rc); err != nil {
		slog.Warn("oauth: register: failed to save client", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("oauth: client registered", "client_id", clientID, "client_name", req.ClientName)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(registerResponse{ //nolint:errcheck
		ClientID:                clientID,
		ClientIDIssuedAt:        rc.CreatedAt.Unix(),
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
	})
}

// writeRegisterError writes an RFC 7591 §3.2.2 JSON error response.
func writeRegisterError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"error":             errCode,
		"error_description": description,
	})
}
