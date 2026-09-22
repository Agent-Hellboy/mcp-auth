package server

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ConsentConfig is the optional connector "consent" block. It customizes the
// browser consent page without forking the template. Nil means the built-in
// copy. website_url and support_url, when set, must be absolute https URLs;
// href escaping is not a substitute for that check.
type ConsentConfig struct {
	DisplayName      string            `json:"display_name,omitempty"`
	WebsiteURL       string            `json:"website_url,omitempty"`
	PageTitle        string            `json:"page_title,omitempty"`
	Subtitle         string            `json:"subtitle,omitempty"`
	IntroParagraphs  []string          `json:"intro_paragraphs,omitempty"`
	Permissions      []string          `json:"permissions,omitempty"`
	ScopeLabels      map[string]string `json:"scope_labels,omitempty"`
	UpstreamSSOLabel string            `json:"upstream_sso_label,omitempty"`
	SupportURL       string            `json:"support_url,omitempty"`
}

func (c *ConsentConfig) validate(name string) error {
	if c == nil {
		return nil
	}
	if c.WebsiteURL != "" {
		if err := validHTTPSURL(c.WebsiteURL); err != nil {
			return fmt.Errorf("connector %q consent website_url: %w", name, err)
		}
	}
	if c.SupportURL != "" {
		if err := validHTTPSURL(c.SupportURL); err != nil {
			return fmt.Errorf("connector %q consent support_url: %w", name, err)
		}
	}
	return nil
}

// validHTTPSURL accepts only absolute https URLs. javascript:, data:, http:,
// and protocol-relative URLs are rejected. An empty string is rejected here;
// callers treat an omitted field as "no link" before calling.
func validHTTPSURL(value string) error {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\t\r\n\\") {
		return errors.New("must be an absolute https URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
		return errors.New("must be an absolute https URL")
	}
	return nil
}

// consentDocumentCSP allows the document's own <style> element and nothing
// else. style-src 'unsafe-inline' is what permits a style element when the
// page has no nonce. There are no event handlers and no external assets.
// script-src is covered by default-src 'none'.
const consentDocumentCSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"

func setConsentDocumentHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", consentDocumentCSP)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}

type consentScope struct {
	Description string
	Raw         string
	Labeled     bool
}

type consentView struct {
	Expired         bool
	Title           string
	ClientName      string
	ClientID        string
	Unverified      bool
	DisplayName     string
	Subtitle        string
	IntroParagraphs []string
	Permissions     []string
	Scopes          []consentScope
	Resource        string
	UpstreamName    string
	NamedUpstream   bool
	WebsiteURL      string
	SupportURL      string
	ID              string
	Action          string
}

func buildConsentView(cfg *ConsentConfig, consentID, action string, request AuthorizationRequest, client Client) consentView {
	resolved := resolvedConsent(cfg)
	scopes := make([]consentScope, 0, len(request.Scope))
	for _, scope := range request.Scope {
		label := ""
		if resolved.ScopeLabels != nil {
			label = strings.TrimSpace(resolved.ScopeLabels[scope])
		}
		if label == "" {
			scopes = append(scopes, consentScope{Description: scope, Raw: scope})
			continue
		}
		scopes = append(scopes, consentScope{Description: label, Raw: scope, Labeled: true})
	}
	clientName := strings.TrimSpace(client.Name)
	if clientName == "" {
		clientName = "Unnamed application"
	}
	upstream := strings.TrimSpace(resolved.UpstreamSSOLabel)
	return consentView{
		Title:           resolved.PageTitle,
		ClientName:      clientName,
		ClientID:        request.ClientID,
		Unverified:      client.DynamicRegistration,
		DisplayName:     resolved.DisplayName,
		Subtitle:        resolved.Subtitle,
		IntroParagraphs: resolved.IntroParagraphs,
		Permissions:     resolved.Permissions,
		Scopes:          scopes,
		Resource:        request.Resource,
		UpstreamName:    upstream,
		NamedUpstream:   upstream != "",
		WebsiteURL:      consentLink(resolved.WebsiteURL),
		SupportURL:      consentLink(resolved.SupportURL),
		ID:              consentID,
		Action:          action,
	}
}

func resolvedConsent(cfg *ConsentConfig) ConsentConfig {
	var in ConsentConfig
	if cfg != nil {
		in = *cfg
		in.IntroParagraphs = append([]string(nil), cfg.IntroParagraphs...)
		in.Permissions = append([]string(nil), cfg.Permissions...)
		if cfg.ScopeLabels != nil {
			in.ScopeLabels = make(map[string]string, len(cfg.ScopeLabels))
			for key, value := range cfg.ScopeLabels {
				in.ScopeLabels[key] = value
			}
		}
	}
	if strings.TrimSpace(in.DisplayName) == "" {
		in.DisplayName = "this service"
	}
	if strings.TrimSpace(in.PageTitle) == "" {
		in.PageTitle = "Authorize access"
	}
	if strings.TrimSpace(in.Subtitle) == "" {
		in.Subtitle = "Review this request, then allow or deny it."
	}
	if len(in.IntroParagraphs) == 0 {
		in.IntroParagraphs = []string{
			"Review the application and the access it is requesting before you continue.",
			"If you do not recognize the application, deny the request.",
		}
	}
	return in
}

func consentLink(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if err := validHTTPSURL(value); err != nil {
		return ""
	}
	return value
}

func writeExpiredConsent(w http.ResponseWriter) {
	setConsentDocumentHeaders(w)
	w.WriteHeader(http.StatusBadRequest)
	_ = consentTemplates.Execute(w, consentView{
		Expired: true,
		Title:   "Consent request expired",
	})
}

func renderConsentPage(w io.Writer, view consentView) error {
	return consentTemplates.Execute(w, view)
}

var consentTemplates = template.Must(template.New("consent").Parse(consentTemplateSource))

const consentTemplateSource = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #eef1f6;
  --surface: #ffffff;
  --text: #17202a;
  --muted: #5c6773;
  --border: #d5dde6;
  --accent: #0b57d0;
  --accent-text: #ffffff;
  --deny-bg: #ffffff;
  --deny-text: #3b4450;
  --deny-border: #6b7785;
  --warn-bg: #fff4d6;
  --warn-text: #5c4300;
  --warn-border: #e6c36a;
  --link: #0b57d0;
  --focus: #0b57d0;
  --code-bg: #f3f5f8;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #101318;
    --surface: #1a1f27;
    --text: #f2f4f8;
    --muted: #b4bdca;
    --border: #323844;
    --accent: #8eb4ff;
    --accent-text: #0d1524;
    --deny-bg: transparent;
    --deny-text: #e7ebf2;
    --deny-border: #9aa6b5;
    --warn-bg: #3a2f12;
    --warn-text: #f6e2a8;
    --warn-border: #8a7040;
    --link: #8eb4ff;
    --focus: #b9d0ff;
    --code-bg: #12161c;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  line-height: 1.5;
}
main {
  width: min(36rem, calc(100% - 2rem));
  margin: 2.5rem auto;
  padding: 1.75rem 1.5rem 1.5rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 0.9rem;
}
@media (max-width: 40rem) {
  main {
    width: 100%;
    margin: 0;
    min-height: 100vh;
    border-radius: 0;
    border-left: 0;
    border-right: 0;
  }
}
.eyebrow {
  margin: 0;
  color: var(--muted);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
h1 {
  margin: 0.2rem 0 0;
  font-size: 1.8rem;
  line-height: 1.2;
  overflow-wrap: anywhere;
}
h2 {
  margin: 1.4rem 0 0.4rem;
  font-size: 0.95rem;
}
p { margin: 0.65rem 0 0; }
.unverified {
  margin: 0.75rem 0 0;
  padding: 0.7rem 0.85rem;
  background: var(--warn-bg);
  color: var(--warn-text);
  border: 1px solid var(--warn-border);
  border-radius: 0.5rem;
}
.client-id {
  margin: 0.75rem 0 0;
  color: var(--muted);
  font-size: 0.85rem;
}
.client-id-label {
  display: block;
  font-size: 0.75rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.client-id code {
  display: block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  padding: 0.35rem 0.5rem;
  background: var(--code-bg);
  border-radius: 0.35rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
ul { margin: 0.35rem 0 0; padding-left: 1.15rem; }
li { margin: 0.45rem 0; }
.scope-description { display: block; font-weight: 600; }
.scope-raw {
  display: block;
  margin-top: 0.15rem;
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.82rem;
  overflow-wrap: anywhere;
}
.resource {
  margin: 0.35rem 0 0;
  overflow-wrap: anywhere;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.9rem;
}
.links { display: flex; flex-wrap: wrap; gap: 1rem; }
.links a { color: var(--link); }
.actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 1.5rem;
  margin-top: 1.5rem;
  padding-top: 1.25rem;
  border-top: 1px solid var(--border);
}
button {
  font: inherit;
  line-height: 1.2;
  cursor: pointer;
}
button.deny {
  background: var(--deny-bg);
  color: var(--deny-text);
  border: 2px solid var(--deny-border);
  border-radius: 999px;
  min-height: 2.75rem;
  min-width: 7.5rem;
  padding: 0.55rem 1.25rem;
  font-weight: 600;
}
button.allow {
  background: var(--accent);
  color: var(--accent-text);
  border: 2px solid var(--accent);
  border-radius: 0.5rem;
  min-height: 2.75rem;
  min-width: 9rem;
  padding: 0.55rem 1.5rem;
  font-weight: 700;
  margin-left: auto;
}
a:focus,
button:focus {
  outline: 3px solid var(--focus);
  outline-offset: 3px;
}
</style>
</head>
<body>
<main>
{{if .Expired}}
<h1>This authorization request expired</h1>
<p>The consent request expired before it was submitted.</p>
<p>Return to the application and start again from there.</p>
{{else}}
<p class="eyebrow">Application</p>
<h1>{{.ClientName}}</h1>
{{if .Unverified}}
<p class="unverified">Unverified. This name was supplied by the application and has not been verified.</p>
{{end}}
<p class="client-id"><span class="client-id-label">Client ID</span> <code>{{.ClientID}}</code></p>
<p class="request-line">is requesting access to <strong>{{.DisplayName}}</strong>.</p>
{{if .Subtitle}}<p class="subtitle">{{.Subtitle}}</p>{{end}}
{{range .IntroParagraphs}}<p>{{.}}</p>
{{end}}
{{if .Permissions}}
<section>
<h2>What this allows</h2>
<ul class="permissions">
{{range .Permissions}}<li>{{.}}</li>
{{end}}
</ul>
</section>
{{end}}
<section>
<h2>Requested scopes</h2>
{{if .Scopes}}
<ul class="scopes">
{{range .Scopes}}
<li>
<span class="scope-description">{{.Description}}</span>
{{if .Labeled}}<span class="scope-raw">{{.Raw}}</span>{{end}}
</li>
{{end}}
</ul>
{{else}}
<p>No scopes were requested.</p>
{{end}}
</section>
<section>
<h2>Resource</h2>
<p>The access token will be bound to this resource.</p>
<p class="resource">{{.Resource}}</p>
</section>
<section>
<h2>Sign-in</h2>
<p class="upstream">You will be sent to {{if .NamedUpstream}}<strong>{{.UpstreamName}}</strong>{{else}}the upstream identity provider{{end}} to sign in.</p>
</section>
{{if or .WebsiteURL .SupportURL}}
<p class="links">
{{if .WebsiteURL}}<a href="{{.WebsiteURL}}">Website</a>{{end}}
{{if .SupportURL}}<a href="{{.SupportURL}}">Support</a>{{end}}
</p>
{{end}}
<form method="post" action="{{.Action}}">
<input type="hidden" name="consent_id" value="{{.ID}}">
<div class="actions">
<button class="deny" name="decision" value="deny" type="submit">Deny</button>
<button class="allow" name="decision" value="approve" type="submit">Allow</button>
</div>
</form>
{{end}}
</main>
</body>
</html>
`
