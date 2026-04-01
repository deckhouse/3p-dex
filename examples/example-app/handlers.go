package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	data := indexPageData{
		ScopesSupported: a.scopesSupported,
		LogoURI:         dexLogoDataURI,
	}

	if a.sessionAware {
		a.mu.RLock()
		claims := a.lastUserClaims
		checked := a.sessionChecked
		a.mu.RUnlock()

		if claims != nil {
			data.User = claims
			data.LogoutURL = "/app-logout"
		} else if !checked {
			// First visit: redirect to Dex with prompt=none to check session.
			scopes := []string{"openid", "profile", "email"}

			var opts []oauth2.AuthCodeOption
			opts = append(opts, oauth2.SetAuthURLParam("prompt", "none"))
			if a.pkce {
				opts = append(opts, oauth2.SetAuthURLParam("code_challenge", codeChallenge))
				opts = append(opts, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
			}

			authCodeURL := a.oauth2Config(scopes).AuthCodeURL(silentAuthState, opts...)
			http.Redirect(w, r, authCodeURL, http.StatusFound)
			return
		} else {
			data.NotLoggedIn = true
		}
	}

	renderIndex(w, data)
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	// Only use scopes that are checked in the form
	scopes := r.Form["extra_scopes"]
	crossClients := r.Form["cross_client"]

	// Build complete scope list with audience scopes
	scopes = buildScopes(scopes, crossClients)

	connectorID := ""
	if id := r.FormValue("connector_id"); id != "" {
		connectorID = id
	}

	authCodeURL := ""

	var authCodeOptions []oauth2.AuthCodeOption

	if a.pkce {
		authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("code_challenge", codeChallenge))
		authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}

	// Check if offline_access scope is present to determine offline access mode
	hasOfflineAccess := false
	for _, scope := range scopes {
		if scope == "offline_access" {
			hasOfflineAccess = true
			break
		}
	}

	if hasOfflineAccess && !a.offlineAsScope {
		// Provider uses access_type=offline instead of offline_access scope
		authCodeOptions = append(authCodeOptions, oauth2.AccessTypeOffline)
		// Remove offline_access from scopes as it's not supported
		filteredScopes := make([]string, 0, len(scopes))
		for _, scope := range scopes {
			if scope != "offline_access" {
				filteredScopes = append(filteredScopes, scope)
			}
		}
		scopes = filteredScopes
	}

	authCodeURL = a.oauth2Config(scopes).AuthCodeURL(exampleAppState, authCodeOptions...)

	// Parse the auth code URL and safely add connector_id parameter if provided
	u, err := url.Parse(authCodeURL)
	if err != nil {
		http.Error(w, "Failed to parse auth URL", http.StatusInternalServerError)
		return
	}

	if connectorID != "" {
		query := u.Query()
		query.Set("connector_id", connectorID)
		u.RawQuery = query.Encode()
	}

	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		token *oauth2.Token
	)

	ctx := oidc.ClientContext(r.Context(), a.client)
	oauth2Config := a.oauth2Config(nil)
	switch r.Method {
	case http.MethodGet:
		state := r.FormValue("state")

		// Silent auth callback (prompt=none).
		if state == silentAuthState {
			claims, rawIDToken := a.exchangeSilentAuth(ctx, r, oauth2Config)
			a.setSilentAuthResult(claims, rawIDToken)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Normal authorization code callback.
		if errMsg := r.FormValue("error"); errMsg != "" {
			http.Error(w, errMsg+": "+r.FormValue("error_description"), http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		if code == "" {
			http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
			return
		}
		if state != exampleAppState {
			http.Error(w, fmt.Sprintf("expected state %q got %q", exampleAppState, state), http.StatusBadRequest)
			return
		}

		var authCodeOptions []oauth2.AuthCodeOption
		if a.pkce {
			authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
		}

		token, err = oauth2Config.Exchange(ctx, code, authCodeOptions...)
	case http.MethodPost:
		// Form request from frontend to refresh a token.
		refresh := r.FormValue("refresh_token")
		if refresh == "" {
			http.Error(w, fmt.Sprintf("no refresh_token in request: %q", r.Form), http.StatusBadRequest)
			return
		}
		t := &oauth2.Token{
			RefreshToken: refresh,
			Expiry:       time.Now().Add(-time.Hour),
		}
		token, err = oauth2Config.TokenSource(ctx, t).Token()
	default:
		http.Error(w, fmt.Sprintf("method not implemented: %s", r.Method), http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		return
	}

	parseAndRenderToken(w, r, a, token)
}

// exchangeSilentAuth attempts a token exchange for a silent auth callback.
// Returns the parsed claims and raw ID token on success, or (nil, "") on any failure.
func (a *app) exchangeSilentAuth(ctx context.Context, r *http.Request, oauth2Config *oauth2.Config) (*userClaims, string) {
	if r.FormValue("error") != "" {
		return nil, ""
	}

	code := r.FormValue("code")
	if code == "" {
		return nil, ""
	}

	var opts []oauth2.AuthCodeOption
	if a.pkce {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	}

	token, err := oauth2Config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, ""
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Printf("silent auth: no id_token in response")
		return nil, ""
	}

	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return nil, ""
	}

	var claims userClaims
	_ = idToken.Claims(&claims)
	return &claims, rawIDToken
}

// setSilentAuthResult persists the silent auth outcome and marks the session as checked.
func (a *app) setSilentAuthResult(claims *userClaims, rawIDToken string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastUserClaims = claims
	if rawIDToken != "" {
		a.lastIDToken = rawIDToken
	}
	a.sessionChecked = true
}

func (a *app) handleAppLogout(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	idToken := a.lastIDToken
	a.lastUserClaims = nil
	a.lastIDToken = ""
	a.sessionChecked = false
	a.mu.Unlock()

	if a.endSessionEndpoint == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	logoutURL, err := url.Parse(a.endSessionEndpoint)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	q := logoutURL.Query()
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	// Derive app base URL from redirect URI for post-logout redirect.
	if appURL, err := url.Parse(a.redirectURI); err == nil {
		appURL.Path = "/"
		appURL.RawQuery = ""
		q.Set("post_logout_redirect_uri", appURL.String())
	}
	logoutURL.RawQuery = q.Encode()
	http.Redirect(w, r, logoutURL.String(), http.StatusFound)
}
