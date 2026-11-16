package oauth

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateIssuer reports whether issuer can be this server's issuer
// identifier (RFC 8414 section 2), the base every endpoint in the metadata is
// built on. It must be an absolute http or https URL with a host, with no
// query and no fragment: with either, the endpoints are the issuer plus
// "/oauth/..." inside the query or fragment, and no client reaches them. A
// path is allowed.
//
// Three forms that work today are accepted, and [New] logs a warning for each:
// http on a host that is not loopback (codes and tokens travel in the clear),
// user info (published in the metadata), and a trailing slash (the endpoints
// get a double slash, which reaches the server only through a redirect).
//
// The error names the issuer, with any password redacted, and the part that
// is wrong.
func ValidateIssuer(issuer string) error {
	p, err := url.Parse(issuer)
	if err == nil {
		issuer = p.Redacted()
	}
	if err != nil || !p.IsAbs() || p.Host == "" || p.Hostname() == "" {
		return fmt.Errorf("oauth: Config.Issuer %q is not an absolute URL with a host", issuer)
	}
	switch strings.ToLower(p.Scheme) {
	case "https", "http":
	default:
		return fmt.Errorf("oauth: Config.Issuer %q must use https or http, not %q", issuer, p.Scheme)
	}
	switch {
	case p.RawQuery != "" || p.ForceQuery:
		return fmt.Errorf("oauth: Config.Issuer %q must not have a query", issuer)
	case p.Fragment != "" || strings.Contains(issuer, "#"):
		return fmt.Errorf("oauth: Config.Issuer %q must not have a fragment", issuer)
	}
	return nil
}

// issuerWarnings lists what is wrong with a valid issuer p that still works,
// one sentence each, for New to log.
func issuerWarnings(p *url.URL, issuer string) []string {
	var out []string
	if strings.EqualFold(p.Scheme, "http") && !isLoopbackHost(p.Hostname()) {
		out = append(out, "oauth: Config.Issuer uses http on a host that is not loopback: codes and tokens travel in the clear")
	}
	if p.User != nil {
		out = append(out, "oauth: Config.Issuer carries user info, which the metadata publishes to anyone")
	}
	if strings.HasSuffix(issuer, "/") {
		out = append(out, "oauth: Config.Issuer ends with a slash: the endpoints get a double slash, and a client that does not follow a 307 redirect cannot reach them")
	}
	return out
}

// isLoopbackHost reports whether host (without port) is localhost or a
// loopback IP address.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
