package server

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// loopbackPortWildcard matches the allowlist syntax http://<loopback>:*[/path].
// Go's url.Parse rejects "*" as a port, so this form is recognized before parsing.
// The host is either an IPv6 literal in brackets or a hostname with no port.
var loopbackPortWildcard = regexp.MustCompile(`^http://(\[[^\]]+\]|[^/?:#]+):\*(/[^?#]*)?(\?[^#]*)?$`)

// parseClientRedirect reports whether value is a structurally valid redirect URI.
// anyPath is true only for an explicit http://<loopback>:* entry with no path,
// which matches any path on that host. A path in the entry, including :*/callback,
// stays exact.
func parseClientRedirect(value string) (parsed *url.URL, anyPath bool, err error) {
	if value == "" || strings.Contains(value, "#") {
		return nil, false, errors.New("must be an absolute URI with no fragment")
	}
	if strings.Contains(value, ":*") {
		return parseLoopbackPortWildcard(value)
	}
	parsed, err = url.Parse(value)
	if err != nil || parsed.Scheme == "" || !parsed.IsAbs() || parsed.Fragment != "" {
		return nil, false, errors.New("must be an absolute URI with no fragment")
	}
	switch parsed.Scheme {
	case "https":
		if parsed.Host == "" {
			return nil, false, errors.New("must be an absolute URI with no fragment")
		}
	case "http":
		// RFC 8252 §7.3: loopback only, both address families. url.Parse reports
		// "::1" from Hostname() without brackets.
		if !isLoopbackHost(parsed.Hostname()) {
			return nil, false, errors.New("must be an absolute URI with no fragment")
		}
	default:
		// RFC 8252 §7.1 private-use URI scheme. An empty authority
		// (com.example.app:/oauth/callback) is legitimate; registration and the
		// allowlist share this predicate so either call site can admit it.
	}
	return parsed, false, nil
}

func parseLoopbackPortWildcard(value string) (*url.URL, bool, error) {
	match := loopbackPortWildcard.FindStringSubmatch(value)
	if match == nil {
		return nil, false, errors.New("must be an absolute URI with no fragment")
	}
	host, path, query := match[1], match[2], match[3]
	rewritten := "http://" + host + path + query
	parsed, err := url.Parse(rewritten)
	if err != nil || !isLoopbackHost(parsed.Hostname()) {
		return nil, false, errors.New("must be an absolute URI with no fragment")
	}
	// No path on a :* entry means any path. A path pins the match.
	return parsed, path == "", nil
}

// validRedirect is the registration predicate. It accepts the same URIs as
// validAbsoluteURI.
func validRedirect(value string) bool {
	_, _, err := parseClientRedirect(value)
	return err == nil
}

// validAbsoluteURI is the allowlist predicate. It is the same structural check
// as validRedirect, including loopback :* wildcards and private-use URIs with
// an empty authority.
func validAbsoluteURI(value string) error {
	_, _, err := parseClientRedirect(value)
	return err
}

// validUpstreamCallbackURI checks this server's own identity-callback allowlist.
// Those URLs are http(s) endpoints with a host, not client redirect syntax.
func validUpstreamCallbackURI(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Fragment != "" || parsed.Host == "" {
		return errors.New("must be an absolute URI with no fragment")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errors.New("must be an absolute URI with no fragment")
	}
	return nil
}

// redirectMatches reports whether candidate satisfies one allowlist entry.
// https and private-use schemes compare as exact strings. An http loopback
// entry compares scheme, hostname, and path, and ignores the port (RFC 8252
// §7.3). An explicit :* with no path also ignores the path, which is the
// documented "any ephemeral loopback listener" entry.
func redirectMatches(pattern, candidate string) bool {
	if pattern == candidate {
		return true
	}
	parsedPattern, anyPath, err := parseClientRedirect(pattern)
	if err != nil || parsedPattern.Scheme != "http" || !isLoopbackHost(parsedPattern.Hostname()) {
		return false
	}
	parsedCandidate, _, err := parseClientRedirect(candidate)
	if err != nil || parsedCandidate.Scheme != "http" || parsedCandidate.Hostname() != parsedPattern.Hostname() {
		return false
	}
	if anyPath {
		return true
	}
	return parsedPattern.EscapedPath() == parsedCandidate.EscapedPath() && parsedPattern.RawQuery == parsedCandidate.RawQuery
}

func redirectAllowed(allowlist []string, redirectURI string) bool {
	for _, entry := range allowlist {
		if redirectMatches(entry, redirectURI) {
			return true
		}
	}
	return false
}
