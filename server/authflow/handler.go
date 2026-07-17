// Package authflow implements dex's interactive browser-facing authorization
// flow: the /auth authorization endpoint, connector and password login, the
// session (SSO) shortcut, MFA (TOTP and WebAuthn), the consent/approval screen,
// and RP-initiated logout.
//
// The flow is a state machine over a storage.AuthRequest. Two abstractions keep
// it honest:
//
//   - nextAuthStep (nextstep.go) is the single, data-oriented decision for what
//     a logged-in request needs next — an MFA factor, consent, or issuing the
//     code — in the spirit of zitadel's nextSteps. The handlers dispatch on its
//     typed result; they don't re-derive the decision.
//   - responseTypeHandler (approval.go) issues the authorization response, one
//     self-selecting handler per OAuth2 response_type, in the spirit of fosite's
//     AuthorizeEndpointHandler.
package authflow

import (
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/dexidp/dex/server/connectors"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/server/router"
	"github.com/dexidp/dex/server/signer"
	"github.com/dexidp/dex/server/templates"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/storage"
)

// Config holds everything the interactive auth flow depends on. It is the narrow
// contract between the top-level Server and this package: NewHandler copies these
// into a Handler, and the flow never reaches back into the Server.
type Config struct {
	IssuerURL              url.URL
	Connectors             *connectors.Cache
	Storage                storage.Storage
	Templates              *templates.Templates
	Signer                 signer.Signer
	Issuer                 *tokens.Issuer
	Now                    func() time.Time
	Logger                 *slog.Logger
	SkipApproval           bool
	AlwaysShowLogin        bool
	SupportedResponseTypes map[string]bool
	PKCE                   PKCEConfig
	AuthRequestsValidFor   time.Duration
	SessionConfig          *SessionConfig
	MFAProviders           map[string]MFAProvider
	DefaultMFAChain        []string
}

// Handler serves the interactive authorization flow.
type Handler struct {
	issuerURL              url.URL
	connectors             *connectors.Cache
	storage                storage.Storage
	templates              *templates.Templates
	signer                 signer.Signer
	issuer                 *tokens.Issuer
	now                    func() time.Time
	logger                 *slog.Logger
	skipApproval           bool
	alwaysShowLogin        bool
	supportedResponseTypes map[string]bool
	pkce                   PKCEConfig
	authRequestsValidFor   time.Duration
	sessionConfig          *SessionConfig
	mfaProviders           map[string]MFAProvider
	defaultMFAChain        []string
}

// NewHandler builds the interactive auth-flow handler from its configuration.
func NewHandler(c Config) *Handler {
	return &Handler{
		issuerURL:              c.IssuerURL,
		connectors:             c.Connectors,
		storage:                c.Storage,
		templates:              c.Templates,
		signer:                 c.Signer,
		issuer:                 c.Issuer,
		now:                    c.Now,
		logger:                 c.Logger,
		skipApproval:           c.SkipApproval,
		alwaysShowLogin:        c.AlwaysShowLogin,
		supportedResponseTypes: c.SupportedResponseTypes,
		pkce:                   c.PKCE,
		authRequestsValidFor:   c.AuthRequestsValidFor,
		sessionConfig:          c.SessionConfig,
		mfaProviders:           c.MFAProviders,
		defaultMFAChain:        c.DefaultMFAChain,
	}
}

// Mount registers the interactive auth-flow routes. The logout and MFA endpoints
// require sessions (they are only wired when a session config is present).
func (h *Handler) Mount(m router.Mux) {
	m.HandleFunc("/auth", h.handleAuthorization)
	m.HandleFunc("/auth/{connector}", h.handleConnectorLogin)
	m.HandleFunc("/auth/{connector}/login", h.handlePasswordLogin)
	m.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// Strip the X-Remote-* headers to prevent security issues on
		// misconfigured authproxy connector setups.
		for key := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-remote-") {
				r.Header.Del(key)
			}
		}
		h.handleConnectorCallback(w, r)
	})
	// For easier connector-specific web server configuration, e.g. for the
	// "authproxy" connector.
	m.HandleFunc("/callback/{connector}", h.handleConnectorCallback)
	m.HandleFunc("/approval", h.handleApproval)

	if h.sessionConfig == nil {
		return
	}
	// The following endpoints require DEX_SESSIONS_ENABLED=true.
	m.HandleFunc("/logout", h.handleLogout)
	m.HandleFunc("/logout/callback", h.handleLogoutCallback)
	m.HandleFunc("/mfa/totp", h.handleTOTP)
	m.HandleFunc("/mfa/webauthn", h.handleWebAuthn)
	m.HandleFunc("/mfa/webauthn/register/begin", h.handleWebAuthnRegisterBegin)
	m.HandleFunc("/mfa/webauthn/register/finish", h.handleWebAuthnRegisterFinish)
	m.HandleFunc("/mfa/webauthn/login/begin", h.handleWebAuthnLoginBegin)
	m.HandleFunc("/mfa/webauthn/login/finish", h.handleWebAuthnLoginFinish)
}

// absPath returns the issuer path joined with the given path items.
func (h *Handler) absPath(pathItems ...string) string {
	paths := make([]string, len(pathItems)+1)
	paths[0] = h.issuerURL.Path
	copy(paths[1:], pathItems)
	return path.Join(paths...)
}

// absURL returns the absolute issuer URL for the given path items.
func (h *Handler) absURL(pathItems ...string) string {
	u := h.issuerURL
	u.Path = h.absPath(pathItems...)
	return u.String()
}

// buildApprovalURL builds an HMAC-protected approval URL.
func (h *Handler) buildApprovalURL(authReq storage.AuthRequest) string {
	v := url.Values{}
	v.Set("req", authReq.ID)
	v.Set("hmac", internal.ComputeHMAC(authReq.HMACKey, authReq.ID, ""))
	return h.absPath("/approval") + "?" + v.Encode()
}

// SessionConfig holds resolved session configuration.
type SessionConfig struct {
	CookieName                 string
	CookieEncryptionKey        []byte
	AbsoluteLifetime           time.Duration
	ValidIfNotUsedFor          time.Duration
	RememberMeCheckedByDefault bool
	// SSOSharedWithDefault is the default SSO sharing policy for clients without explicit SSOSharedWith.
	// "all" = share with all clients, "none" or "" = share with no one (default).
	SSOSharedWithDefault string
}

// PKCEConfig holds PKCE (Proof Key for Code Exchange) settings.
type PKCEConfig struct {
	// If true, PKCE is required for all authorization code flows.
	Enforce bool
	// Supported code challenge methods. Defaults to ["S256", "plain"].
	CodeChallengeMethodsSupported []string
}
