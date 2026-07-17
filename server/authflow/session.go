package authflow

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

// rememberMeDefault returns a pointer to the default remember-me value if sessions are enabled, nil otherwise.
func (h *Handler) rememberMeDefault() *bool {
	if h.sessionConfig == nil {
		return nil
	}
	v := h.sessionConfig.RememberMeCheckedByDefault
	return &v
}

// remoteIP returns the real IP from context (set by parseRealIP middleware) or falls back to r.RemoteAddr.
func remoteIP(r *http.Request) string {
	if ip, ok := r.Context().Value(RequestKeyRemoteIP).(string); ok && ip != "" {
		return ip
	}
	return r.RemoteAddr
}

func (h *Handler) sessionCookiePath() string {
	if h.issuerURL.Path == "" {
		return "/"
	}
	return h.issuerURL.Path
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, userID, connectorID, nonce string, rememberMe bool) {
	cookie := &http.Cookie{
		Name:     h.sessionConfig.CookieName,
		Value:    internal.SessionCookieValue(userID, connectorID, nonce, h.sessionConfig.CookieEncryptionKey),
		Path:     h.sessionCookiePath(),
		HttpOnly: true,
		Secure:   h.issuerURL.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
	}
	if rememberMe {
		cookie.MaxAge = int(h.sessionConfig.AbsoluteLifetime.Seconds())
	}
	http.SetCookie(w, cookie)
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.sessionConfig.CookieName,
		Value:    "",
		Path:     h.sessionCookiePath(),
		HttpOnly: true,
		Secure:   h.issuerURL.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// getValidSession returns a valid, non-expired session or nil.
// It parses the session cookie to extract (userID, connectorID, nonce),
// looks up the session by composite key, and verifies the nonce.
// Invalid or expired session cookies are cleared automatically.
func (h *Handler) getValidSession(ctx context.Context, w http.ResponseWriter, r *http.Request) *storage.AuthSession {
	if h.sessionConfig == nil {
		return nil
	}

	cookie, err := r.Cookie(h.sessionConfig.CookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}

	userID, connectorID, nonce, err := internal.ParseSessionCookie(cookie.Value, h.sessionConfig.CookieEncryptionKey)
	if err != nil {
		h.logger.DebugContext(ctx, "invalid session cookie format", "err", err)
		h.clearSessionCookie(w)
		return nil
	}

	session, err := h.storage.GetAuthSession(ctx, userID, connectorID)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			h.logger.ErrorContext(ctx, "failed to get auth session", "err", err)
		}
		h.clearSessionCookie(w)
		return nil
	}

	// Verify nonce to prevent cookie forgery.
	// Use constant-time comparison to prevent timing attacks that could
	// allow an attacker to recover the nonce byte-by-byte.
	if subtle.ConstantTimeCompare([]byte(session.Nonce), []byte(nonce)) != 1 {
		h.logger.DebugContext(ctx, "auth session nonce mismatch")
		h.clearSessionCookie(w)
		return nil
	}

	now := h.now()

	// Check absolute lifetime using the stored expiry (set once at creation).
	if !session.AbsoluteExpiry.IsZero() && now.After(session.AbsoluteExpiry) {
		h.logger.InfoContext(ctx, "auth session expired (absolute lifetime)",
			"user_id", session.UserID, "connector_id", session.ConnectorID)
		if err := h.storage.DeleteAuthSession(ctx, session.UserID, session.ConnectorID); err != nil {
			h.logger.DebugContext(ctx, "failed to delete expired auth session", "err", err)
		}
		h.clearSessionCookie(w)
		return nil
	}

	// Check idle timeout using the stored expiry (updated on every activity).
	if !session.IdleExpiry.IsZero() && now.After(session.IdleExpiry) {
		h.logger.InfoContext(ctx, "auth session expired (idle timeout)",
			"user_id", session.UserID, "connector_id", session.ConnectorID)
		if err := h.storage.DeleteAuthSession(ctx, session.UserID, session.ConnectorID); err != nil {
			h.logger.DebugContext(ctx, "failed to delete expired auth session", "err", err)
		}
		h.clearSessionCookie(w)
		return nil
	}

	return &session
}

// getValidAuthSession returns a valid session matching the auth request's connector, or nil.
func (h *Handler) getValidAuthSession(ctx context.Context, w http.ResponseWriter, r *http.Request, authReq *storage.AuthRequest) *storage.AuthSession {
	session := h.getValidSession(ctx, w, r)
	if session == nil {
		return nil
	}

	// Only reuse sessions from the same connector.
	if session.ConnectorID != authReq.ConnectorID {
		return nil
	}

	return session
}

// createOrUpdateAuthSession creates a new session or updates an existing one
// after a successful login, and sets the session cookie.
// rememberMe controls whether the cookie is persistent (survives browser close).
func (h *Handler) createOrUpdateAuthSession(ctx context.Context, r *http.Request, w http.ResponseWriter, authReq storage.AuthRequest, rememberMe bool) error {
	if h.sessionConfig == nil {
		return nil
	}

	now := h.now()
	userID := authReq.Claims.UserID
	connectorID := authReq.ConnectorID

	clientState := &storage.ClientAuthState{
		Active:       true,
		ExpiresAt:    now.Add(h.sessionConfig.AbsoluteLifetime),
		LastActivity: now,
	}

	// Try to reuse existing session for this (userID, connectorID).
	session, err := h.storage.GetAuthSession(ctx, userID, connectorID)
	if err == nil {
		// Session exists, update it.
		h.logger.DebugContext(ctx, "updating existing auth session",
			"user_id", userID, "connector_id", connectorID, "client_id", authReq.ClientID)

		if err := h.storage.UpdateAuthSession(ctx, userID, connectorID, func(old storage.AuthSession) (storage.AuthSession, error) {
			old.LastActivity = now
			old.IdleExpiry = now.Add(h.sessionConfig.ValidIfNotUsedFor)
			if old.ClientStates == nil {
				old.ClientStates = make(map[string]*storage.ClientAuthState)
			}
			old.ClientStates[authReq.ClientID] = clientState
			return old, nil
		}); err != nil {
			return fmt.Errorf("update auth session: %w", err)
		}

		h.setSessionCookie(w, userID, connectorID, session.Nonce, rememberMe)
		return nil
	}

	// Unexpected error, exit the method.
	if !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("get auth session: %w", err)
	}

	nonce := storage.NewID()
	newSession := storage.AuthSession{
		UserID:      userID,
		ConnectorID: connectorID,
		Nonce:       nonce,
		ClientStates: map[string]*storage.ClientAuthState{
			authReq.ClientID: clientState,
		},
		CreatedAt:      now,
		LastActivity:   now,
		IPAddress:      remoteIP(r),
		UserAgent:      r.UserAgent(),
		AbsoluteExpiry: now.Add(h.sessionConfig.AbsoluteLifetime),
		IdleExpiry:     now.Add(h.sessionConfig.ValidIfNotUsedFor),
	}

	if err := h.storage.CreateAuthSession(ctx, newSession); err != nil {
		return fmt.Errorf("create auth session: %w", err)
	}

	h.logger.DebugContext(ctx, "created new auth session",
		"user_id", userID, "connector_id", connectorID, "client_id", authReq.ClientID)
	h.setSessionCookie(w, userID, connectorID, nonce, rememberMe)
	return nil
}

// trySessionLogin checks if the user has a valid session for the same connector.
// If so, it finalizes login from the stored identity and returns a redirect URL.
// Returns ("", false) if session-based login is not possible.
func (h *Handler) trySessionLogin(ctx context.Context, r *http.Request, w http.ResponseWriter, authReq *storage.AuthRequest) (string, bool) {
	session := h.getValidAuthSession(ctx, w, r, authReq)
	return h.trySessionLoginWithSession(ctx, r, w, authReq, session)
}

// clientSharesSessionWith checks if sourceClient shares its session with targetClientID.
// SSO sharing is unidirectional: source sharing with target does NOT mean target shares with source.
func (h *Handler) clientSharesSessionWith(sourceClient storage.Client, targetClientID string) bool {
	ssoSharedWith := sourceClient.SSOSharedWith

	// If client has no explicit ssoSharedWith, use default from session config.
	if ssoSharedWith == nil {
		switch h.sessionConfig.SSOSharedWithDefault {
		case "all":
			return true
		default: // "none" or ""
			return false
		}
	}

	// Explicit empty slice means share with no one.
	if len(ssoSharedWith) == 0 {
		return false
	}

	for _, peer := range ssoSharedWith {
		if peer == "*" || peer == targetClientID {
			return true
		}
	}
	return false
}

// findSSOSession checks whether any active client in the session shares its
// authentication with targetClientID via the ssoSharedWith policy.
//
// Note: the caller already has the target client loaded (for AllowedConnectors
// validation), but here we need the *source* client configs - those are the
// clients the user previously authenticated for, and their ssoSharedWith
// policies determine whether SSO is allowed. These are different clients,
// so the GetClient calls below are not redundant.
func (h *Handler) findSSOSession(ctx context.Context, session *storage.AuthSession, targetClientID string) *storage.ClientAuthState {
	now := h.now()

	for sourceClientID, state := range session.ClientStates {
		if !state.Active || now.After(state.ExpiresAt) {
			continue
		}

		// Only directly-authenticated states may act as SSO sources. Skipping
		// SSO-derived states keeps sharing unidirectional and prevents transitive
		// A->B->C chains (a user authenticated only to A must not be SSO'd into C
		// just because B shares with C).
		if state.ViaSSO {
			continue
		}

		sourceClient, err := h.storage.GetClient(ctx, sourceClientID)
		if err != nil {
			h.logger.DebugContext(ctx, "session: SSO lookup failed to get source client",
				"source_client_id", sourceClientID, "err", err)
			continue
		}

		if h.clientSharesSessionWith(sourceClient, targetClientID) {
			return state
		}
	}

	return nil
}

// trySessionLoginWithSession is like trySessionLogin but accepts a pre-retrieved session.
// This allows callers to inspect the session (e.g., for id_token_hint comparison) before
// attempting session-based login.
func (h *Handler) trySessionLoginWithSession(ctx context.Context, r *http.Request, w http.ResponseWriter, authReq *storage.AuthRequest, session *storage.AuthSession) (string, bool) {
	if session == nil {
		return "", false
	}

	now := h.now()

	clientState, ok := session.ClientStates[authReq.ClientID]
	fallbackToSSO := !ok || !clientState.Active || now.After(clientState.ExpiresAt)

	if fallbackToSSO {
		// No direct session for this client — try SSO from a sharing client.
		sourceState := h.findSSOSession(ctx, session, authReq.ClientID)
		if sourceState == nil {
			return "", false
		}

		// Cap the derived state expiry at min(configured lifetime, source state expiry).
		expiresAt := now.Add(h.sessionConfig.AbsoluteLifetime)
		if sourceState.ExpiresAt.Before(expiresAt) {
			expiresAt = sourceState.ExpiresAt
		}

		// Create a new client state for the target client via SSO.
		if err := h.storage.UpdateAuthSession(ctx, session.UserID, session.ConnectorID, func(old storage.AuthSession) (storage.AuthSession, error) {
			if old.ClientStates == nil {
				old.ClientStates = make(map[string]*storage.ClientAuthState)
			}
			old.ClientStates[authReq.ClientID] = &storage.ClientAuthState{
				Active:       true,
				ExpiresAt:    expiresAt,
				LastActivity: now,
				ViaSSO:       true,
			}
			old.LastActivity = now
			old.IdleExpiry = now.Add(h.sessionConfig.ValidIfNotUsedFor)
			return old, nil
		}); err != nil {
			h.logger.ErrorContext(ctx, "session: failed to create SSO client state", "err", err)
			return "", false
		}

		h.logger.DebugContext(ctx, "session: SSO login from sharing client",
			"user_id", session.UserID, "connector_id", session.ConnectorID, "client_id", authReq.ClientID)
	}

	// Load identity from storage (same path for direct and SSO login).
	ui, err := h.storage.GetUserIdentity(ctx, session.UserID, session.ConnectorID)
	if err != nil {
		h.logger.ErrorContext(ctx, "session: failed to get user identity", "err", err)
		return "", false
	}

	// Check max_age: if the user's last authentication is too old, force re-auth.
	if authReq.MaxAge >= 0 {
		if now.Sub(ui.LastLogin) > time.Duration(authReq.MaxAge)*time.Second {
			return "", false
		}
	}

	if !fallbackToSSO {
		h.logger.DebugContext(ctx, "session: re-authenticated from session",
			"user_id", session.UserID, "connector_id", session.ConnectorID)
	}

	return h.finishSessionLogin(ctx, r, w, authReq, session, &ui, now)
}

// finishSessionLogin completes a session-based login (direct or SSO) by updating the auth request
// with the user's identity, refreshing session activity, and returning the appropriate redirect URL.
func (h *Handler) finishSessionLogin(ctx context.Context, r *http.Request, w http.ResponseWriter, authReq *storage.AuthRequest, session *storage.AuthSession, ui *storage.UserIdentity, now time.Time) (string, bool) {
	claims := storage.Claims{
		UserID:            ui.Claims.UserID,
		Username:          ui.Claims.Username,
		PreferredUsername: ui.Claims.PreferredUsername,
		Email:             ui.Claims.Email,
		EmailVerified:     ui.Claims.EmailVerified,
		Groups:            ui.Claims.Groups,
	}

	// Update AuthRequest with stored identity and auth_time from last login.
	if err := h.storage.UpdateAuthRequest(ctx, authReq.ID, func(a storage.AuthRequest) (storage.AuthRequest, error) {
		a.LoggedIn = true
		a.Claims = claims
		a.ConnectorID = session.ConnectorID
		a.AuthTime = ui.LastLogin
		return a, nil
	}); err != nil {
		h.logger.ErrorContext(ctx, "session: failed to update auth request", "err", err)
		return "", false
	}

	// Update session activity.
	_ = h.storage.UpdateAuthSession(ctx, session.UserID, session.ConnectorID, func(old storage.AuthSession) (storage.AuthSession, error) {
		old.LastActivity = now
		old.IdleExpiry = now.Add(h.sessionConfig.ValidIfNotUsedFor)
		if cs, ok := old.ClientStates[authReq.ClientID]; ok {
			cs.LastActivity = now
		}
		return old, nil
	})

	// Re-read to get the updated AuthRequest (LoggedIn, Claims, ConnectorID set above),
	// then let the shared decision pick the next step.
	updated, err := h.storage.GetAuthRequest(ctx, authReq.ID)
	if err != nil {
		h.logger.ErrorContext(ctx, "session: failed to get auth request", "err", err)
		return "", false
	}
	step, err := h.nextAuthStep(ctx, &updated)
	if err != nil {
		h.logger.ErrorContext(ctx, "session: failed to determine next auth step", "err", err)
		return "", false
	}
	switch st := step.(type) {
	case mfaStep:
		return h.buildMFARedirectURL(updated, st.authenticator), true
	case issueStep:
		h.sendCodeResponse(w, r, updated)
		return "", true
	default: // approvalStep
		return h.buildApprovalURL(updated), true
	}
}

// updateSessionTokenIssuedAt updates the session's LastTokenIssuedAt for the given client.
func (h *Handler) updateSessionTokenIssuedAt(r *http.Request, clientID string) {
	if h.sessionConfig == nil {
		return
	}

	cookie, err := r.Cookie(h.sessionConfig.CookieName)
	if err != nil || cookie.Value == "" {
		return
	}

	userID, connectorID, _, err := internal.ParseSessionCookie(cookie.Value, h.sessionConfig.CookieEncryptionKey)
	if err != nil {
		return
	}

	now := h.now()
	_ = h.storage.UpdateAuthSession(r.Context(), userID, connectorID, func(old storage.AuthSession) (storage.AuthSession, error) {
		old.LastActivity = now
		old.IdleExpiry = now.Add(h.sessionConfig.ValidIfNotUsedFor)
		if cs, ok := old.ClientStates[clientID]; ok {
			cs.LastTokenIssuedAt = now
			cs.LastActivity = now
		}
		return old, nil
	})
}
