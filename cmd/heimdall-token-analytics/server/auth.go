// SPDX-License-Identifier: ice License 1.0

package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/nbd-wtf/go-nostr"

	"github.com/ice-blockchain/subzero/model"
)

type (
	// NoAuthRequired is a marker struct to indicate that no authentication is required for the request.
	NoAuthRequired struct{}

	Token interface{}

	NostrToken interface {
		GetMasterPublicKey() string
		GetDeviceKey() string
	}

	XComToken interface {
		GetUserId() string
		GetUserHandle() string
		GetDisplayName() string
		IsVerified() bool
	}

	authContextNIP42 struct {
		Event        *model.Event
		MasterPubKey string
	}
	authContextXCom struct {
		UserInfo *XComUserInfo
	}
	XComUserInfo struct {
		UserId      string `json:"userId"`
		UserHandle  string `json:"userHandle"`
		DisplayName string `json:"displayName"`
		Verified    bool   `json:"verified"`
		Avatar      string `json:"avatar"`
	}
)

const (
	authContextTokenKey   = "_ta_auth_context_token"
	authContextEnabledKey = "_ta_auth_context_enabled"
	xcomAuthScheme        = "X.com"
)

var (
	_ NostrToken = &authContextNIP42{}
	_ XComToken  = &authContextXCom{}

	errAuthInvalidEventSignature = errors.New("invalid NIP42 event signature")
	errAuthNoAttestation         = errors.New("no attestation found in NIP42 event")
	errAuthInvalidKind           = errors.New("invalid NIP42 event kind")
	errAuthValidationFailed      = errors.New("NIP42 chain validation failed")
	errAuthInvalidFormat         = errors.New("invalid token format")
	errAuthXComInvalidToken      = errors.New("invalid X.com token")
	errAuthXComMissingFields     = errors.New("missing required X.com fields")
)

func (a *authContextNIP42) GetMasterPublicKey() string {
	return a.MasterPubKey
}

func (a *authContextNIP42) GetDeviceKey() string {
	return a.Event.PubKey
}

func (a *authContextXCom) GetUserId() string {
	if a.UserInfo != nil {
		return a.UserInfo.UserId
	}

	return ""
}

func (a *authContextXCom) GetUserHandle() string {
	if a.UserInfo != nil {
		return a.UserInfo.UserHandle
	}

	return ""
}

func (a *authContextXCom) GetDisplayName() string {
	if a.UserInfo != nil {
		return a.UserInfo.DisplayName
	}

	return ""
}

func (a *authContextXCom) IsVerified() bool {
	if a.UserInfo != nil {
		return a.UserInfo.Verified
	}

	return false
}

func authGetToken(ctx *gin.Context) Token {
	if ctx == nil {
		return nil
	}

	token, exists := ctx.Get(authContextTokenKey)
	if !exists {
		return nil
	}

	return token.(Token)
}

func AsNostrToken(token Token) (NostrToken, bool) {
	if token == nil {
		return nil, false
	}
	nostrToken, ok := token.(NostrToken)

	return nostrToken, ok
}

func AsXComToken(token Token) (XComToken, bool) {
	if token == nil {
		return nil, false
	}
	xcomToken, ok := token.(XComToken)

	return xcomToken, ok
}

func authIsEnabled(ctx *gin.Context) bool {
	if ctx == nil {
		return false
	}

	return ctx.GetBool(authContextEnabledKey)
}

func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(authContextEnabledKey, true)

		token := ctx.GetHeader(`Authorization`)
		if token == "" {
			// No token provided; proceed as unauthorized.
			ctx.Next()
			return
		}
		if strings.HasPrefix(token, xcomAuthScheme+" ") {
			userInfo, err := authValidateXComToken(token)
			if err != nil {
				Unauthorized(err).render(ctx)
				return
			}
			var tokenInfo Token = &authContextXCom{
				UserInfo: userInfo,
			}
			ctx.Set(authContextTokenKey, tokenInfo)
			ctx.Next()

			return
		}

		ev, err := authValidateNIP42Token(token)
		if err != nil {
			Unauthorized(err).render(ctx)
			return
		}

		var tokenInfo Token = &authContextNIP42{
			Event:        ev,
			MasterPubKey: ev.GetMasterPublicKey(),
		}

		ctx.Set(authContextTokenKey, tokenInfo)
		ctx.Next()
	}
}

func authValidateNIP42Token(token string) (*model.Event, error) {
	prefixes := map[string]struct{}{
		"nostr":  {},
		"bearer": {},
	}

	tokenData := strings.SplitN(token, " ", 2)
	if len(tokenData) != 2 {
		return nil, errAuthInvalidFormat
	}

	_, ok := prefixes[strings.ToLower(tokenData[0])]
	if !ok {
		return nil, fmt.Errorf("%w: unknown token prefix %q", errAuthInvalidFormat, tokenData[0])
	}

	jsonData, err := base64.StdEncoding.DecodeString(tokenData[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode NIP42 event: %w", err)
	}

	var ev model.Event
	err = ev.UnmarshalJSON(jsonData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal NIP42 event: %w", err)
	}

	err = authValidateNIP42Event(&ev)
	if err != nil {
		return nil, fmt.Errorf("%q: authorization failed: %w", ev.GetMasterPublicKey(), err)
	}

	return &ev, nil
}

func authValidateNIP42Event(ev *model.Event) error {
	ok, err := ev.CheckSignature()
	if !ok {
		if err == nil {
			err = errAuthInvalidEventSignature
		}
		return fmt.Errorf("signature check failed: %w", err)
	}

	if ev.Kind != nostr.KindClientAuthentication {
		return errAuthInvalidKind
	}

	if ev.PubKey == ev.GetMasterPublicKey() {
		// Master key, no need to validate attestation.
		return nil
	}

	attestationData := ev.GetTag("attestation").Value()
	if attestationData == "" {
		return errAuthNoAttestation
	}

	var attestationEvent model.Event
	if err := attestationEvent.UnmarshalJSON([]byte(attestationData)); err != nil {
		return fmt.Errorf("failed to unmarshal attestation event: %w", err)
	}

	return authValidateEventAttestation(ev, &attestationEvent)
}

func authValidateEventAttestation(authEvent, attestationEvent *model.Event) error {
	ok, err := attestationEvent.CheckSignature()
	if !ok {
		if err == nil {
			err = errAuthInvalidEventSignature
		}
		return fmt.Errorf("attesttion signature check failed: %w", err)
	}

	if attestationEvent.Kind != model.CustomIONKindAttestation {
		return fmt.Errorf("%w: unexpected attestation event kind: %d", errAuthInvalidKind, attestationEvent.Kind)
	} else if owner := authEvent.GetMasterPublicKey(); attestationEvent.PubKey != owner {
		return fmt.Errorf("%w: attestation event has unexpected author %q, expected %q", errAuthValidationFailed, attestationEvent.PubKey, owner)
	}

	records, err := model.ParseAttestationTags(attestationEvent.Tags)
	if err != nil {
		return fmt.Errorf("failed to parse attestation tags: %w", err)
	}

	record, ok := records[authEvent.PubKey]
	if !ok {
		return fmt.Errorf("%w: no attestation record found for pubkey %q", errAuthValidationFailed, authEvent.PubKey)
	}

	now := nostr.Now()
	if record.Revoked != nil && now.After(*record.Revoked) {
		return fmt.Errorf("%w: %q is revoked", errAuthValidationFailed, authEvent.PubKey)
	} else if record.End != nil && now.After(*record.End) {
		return fmt.Errorf("%w: attestation expired for %q", errAuthValidationFailed, authEvent.PubKey)
	} else if record.Start != nil && now.Before(*record.Start) {
		return fmt.Errorf("%w: attestation not yet valid for %q", errAuthValidationFailed, authEvent.PubKey)
	}

	return nil
}

func authValidateXComToken(authHeader string) (*XComUserInfo, error) {
	tokenString := strings.TrimPrefix(authHeader, xcomAuthScheme+" ")
	if tokenString == "" {
		return nil, fmt.Errorf("%w: empty token", errAuthXComInvalidToken)
	}

	jsonData, err := base64.StdEncoding.DecodeString(tokenString)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode base64: %v", errAuthXComInvalidToken, err)
	}

	var userInfo XComUserInfo
	if err := json.Unmarshal(jsonData, &userInfo); err != nil {
		return nil, fmt.Errorf("%w: failed to parse JSON: %v", errAuthXComInvalidToken, err)
	}

	if userInfo.UserId == "" {
		return nil, fmt.Errorf("%w: missing userId", errAuthXComMissingFields)
	}
	if userInfo.UserHandle == "" {
		return nil, fmt.Errorf("%w: missing userHandle", errAuthXComMissingFields)
	}

	return &userInfo, nil
}
