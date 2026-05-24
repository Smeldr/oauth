package forgeoauth

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// authorizeForm is the HTML template rendered at GET /oauth/authorize.
// It presents a minimal form for the user to approve the authorization
// request by submitting their existing Forge bearer token.
var authorizeForm = template.Must(template.New("authorize").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Authorize — Forge</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; background: #f9f9f9; color: #111;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; margin: 0; padding: 1rem; }
  .card { background: #fff; border: 1px solid #e0e0e0; border-radius: 8px;
    padding: 2rem; max-width: 440px; width: 100%; }
  h1 { font-size: 1.25rem; margin: 0 0 0.5rem; }
  .meta { font-size: 0.875rem; color: #555; margin-bottom: 1.5rem; }
  .meta strong { color: #111; }
  label { display: block; font-size: 0.875rem; font-weight: 600; margin-bottom: 0.4rem; }
  input[type=text], input[type=password] {
    width: 100%; padding: 0.5rem 0.75rem; border: 1px solid #ccc;
    border-radius: 4px; font-size: 0.9375rem; }
  input:focus { outline: 2px solid #0070f3; border-color: transparent; }
  button { margin-top: 1.25rem; width: 100%; padding: 0.625rem;
    background: #0070f3; color: #fff; border: none; border-radius: 4px;
    font-size: 1rem; font-weight: 600; cursor: pointer; }
  button:hover { background: #0060d8; }
  .error { color: #c00; font-size: 0.875rem; margin-bottom: 1rem; }
  .scope { font-family: monospace; background: #f0f0f0; padding: 0.125rem 0.375rem;
    border-radius: 3px; }
  .footer { margin-top: 1.5rem; font-size: 0.75rem; color: #888; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <h1>Authorize Access</h1>
  <p class="meta">
    <strong>{{.ClientName}}</strong> is requesting access to your Forge site
    with scope <span class="scope">{{.Scope}}</span>.
  </p>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="response_type"          value="{{.ResponseType}}">
    <input type="hidden" name="client_id"              value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri"           value="{{.RedirectURI}}">
    <input type="hidden" name="scope"                  value="{{.Scope}}">
    <input type="hidden" name="state"                  value="{{.State}}">
    <input type="hidden" name="code_challenge"         value="{{.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method"  value="{{.CodeChallengeMethod}}">
    <label for="bearer_token">Forge Bearer Token</label>
    <input type="password" id="bearer_token" name="bearer_token"
      placeholder="Paste your Forge bearer token" autocomplete="off" required>
    <button type="submit">Approve</button>
  </form>
  <p class="footer">Powered by <a href="https://forge-cms.dev">forge-cms.dev</a></p>
</div>
</body>
</html>
`))

// authorizeParams holds the validated OAuth parameters from an authorization request.
type authorizeParams struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// authorizeFormData is the data passed to the authorizeForm template.
type authorizeFormData struct {
	authorizeParams
	ClientName string
	Error      string
}

// parseAuthorizeParams extracts and validates the required OAuth 2.1
// authorization parameters from the request. Returns an error string
// suitable for user display, or empty string on success.
func parseAuthorizeParams(r *http.Request) (authorizeParams, string) {
	p := authorizeParams{
		ResponseType:        r.FormValue("response_type"),
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}

	if p.ResponseType != "code" {
		return p, "unsupported response_type: must be \"code\""
	}
	if p.ClientID == "" {
		return p, "missing client_id"
	}
	if !strings.HasPrefix(p.ClientID, "https://") {
		return p, "client_id must be an HTTPS URL"
	}
	if p.RedirectURI == "" {
		return p, "missing redirect_uri"
	}
	if p.CodeChallenge == "" {
		return p, "missing code_challenge (PKCE required)"
	}
	if p.CodeChallengeMethod != "S256" {
		return p, "unsupported code_challenge_method: must be \"S256\""
	}
	return p, ""
}

// authorizeGetHandler handles GET /oauth/authorize.
// It validates the request parameters, fetches the CIMD document, and
// renders the authorization form.
func (s *Server) authorizeGetHandler(w http.ResponseWriter, r *http.Request) {
	addr := r.RemoteAddr

	p, errMsg := parseAuthorizeParams(r)
	if errMsg != "" {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	doc, err := s.fetchCIMD(p.ClientID, p.RedirectURI)
	if err != nil {
		slog.Warn("forge-oauth: CIMD fetch failed",
			"client_id", p.ClientID,
			"remote_addr", addr,
			"error", err,
		)
		http.Error(w, "invalid client: "+err.Error(), http.StatusBadRequest)
		return
	}

	data := authorizeFormData{
		authorizeParams: p,
		ClientName:      doc.ClientName,
	}
	if data.ClientName == "" {
		data.ClientName = p.ClientID
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := authorizeForm.Execute(w, data); err != nil {
		slog.Warn("forge-oauth: authorize form render failed",
			"client_id", p.ClientID,
			"remote_addr", addr,
			"error", err,
		)
	}
}

// authorizePostHandler handles POST /oauth/authorize (form submission).
// It re-validates the request, re-fetches the CIMD document, verifies the
// bearer token, generates an authorization code, and redirects.
func (s *Server) authorizePostHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	addr := r.RemoteAddr

	p, errMsg := parseAuthorizeParams(r)
	if errMsg != "" {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	doc, err := s.fetchCIMD(p.ClientID, p.RedirectURI)
	if err != nil {
		slog.Warn("forge-oauth: CIMD fetch failed",
			"client_id", p.ClientID,
			"remote_addr", addr,
			"error", err,
		)
		http.Error(w, "invalid client: "+err.Error(), http.StatusBadRequest)
		return
	}

	bearerToken := r.FormValue("bearer_token")
	if !s.cfg.VerifyBearer(bearerToken) {
		slog.Warn("forge-oauth: bearer token validation failed",
			"client_id", p.ClientID,
			"remote_addr", addr,
		)
		// Re-render form with error message (never disclose why it failed).
		clientName := doc.ClientName
		if clientName == "" {
			clientName = p.ClientID
		}
		data := authorizeFormData{
			authorizeParams: p,
			ClientName:      clientName,
			Error:           "Invalid bearer token. Please paste a valid Forge bearer token.",
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		authorizeForm.Execute(w, data) //nolint:errcheck
		return
	}

	code, err := newToken(32)
	if err != nil {
		slog.Warn("forge-oauth: failed to generate auth code",
			"client_id", p.ClientID,
			"remote_addr", addr,
			"error", err,
		)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	authCode := AuthCode{
		Code:          code,
		ClientID:      p.ClientID,
		RedirectURI:   p.RedirectURI,
		Scope:         p.Scope,
		CodeChallenge: p.CodeChallenge,
		ExpiresAt:     s.now().Add(s.cfg.AuthCodeTTL),
	}
	if err := s.store.SaveCode(r.Context(), authCode); err != nil {
		slog.Warn("forge-oauth: failed to save auth code",
			"client_id", p.ClientID,
			"remote_addr", addr,
			"error", err,
		)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("forge-oauth: authorization granted",
		"client_id", p.ClientID,
		"scope", p.Scope,
		"remote_addr", addr,
	)

	q := url.Values{"code": {code}}
	if p.State != "" {
		q.Set("state", p.State)
	}
	http.Redirect(w, r, p.RedirectURI+"?"+q.Encode(), http.StatusFound)
}
