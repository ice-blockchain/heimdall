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
	Token interface {
		GetMasterPublicKey() string
		GetDevicePublicKey() string
		Platform() string
	}

	// NoAuthRequired is a marker struct to indicate that no authentication is required for the request.
	NoAuthRequired struct{}

	AuthContextNIP42 struct {
		Event        *model.Event
		MasterPubKey string
	}
	AuthContextXcom struct {
		UserInfo *AuthXcomUserInfo
	}
	AuthXcomUserInfo struct {
		UserId      string `json:"userId"`
		UserHandle  string `json:"userHandle"`
		DisplayName string `json:"displayName"`
		Verified    bool   `json:"verified"`
		Avatar      string `json:"avatar"`
	}
)

const (
	TokenTypeIonConnect = "ionconnect"
	TokenTypeXCom       = "xcom"
)
const (
	authContextTokenKey   = "_ta_auth_context_token"
	authContextEnabledKey = "_ta_auth_context_enabled"

	authHeaderName = `Authorization`
)

var (
	_ Token = &AuthContextNIP42{}
	_ Token = &AuthContextXcom{}

	errAuthInvalidEventSignature = errors.New("nip42: invalid event signature")
	errAuthNoAttestation         = errors.New("nip42: no attestation found in the event tags")
	errAuthInvalidKind           = errors.New("nip42: invalid event kind")
	errAuthValidationFailed      = errors.New("nip42: chain validation failed")
	errAuthInvalidFormat         = errors.New("invalid token format")
	errAuthXComMissingFields     = errors.New("x.com: missing required fields")
)

func (a *AuthContextNIP42) GetMasterPublicKey() string {
	return a.MasterPubKey
}

func (a *AuthContextNIP42) GetDevicePublicKey() string {
	return a.Event.PubKey
}
func (a *AuthContextNIP42) Platform() string {
	return TokenTypeIonConnect
}

func (a *AuthContextXcom) GetMasterPublicKey() string {
	if a.UserInfo != nil {
		return a.UserInfo.UserId
	}
	return ""
}

func (a *AuthContextXcom) GetDevicePublicKey() string {
	if a.UserInfo != nil {
		return a.UserInfo.UserId
	}
	return ""
}
func (a *AuthContextXcom) Platform() string {
	return TokenTypeXCom
}

func RequireAuth(ctx *gin.Context) (Token, *ResponseError) {
	header := ctx.GetHeader(authHeaderName)
	if header == "" {
		return nil, Forbidden(errAuthRequired)
	}
	token, err := authValidateAuthHeader(header)
	if err != nil {
		return nil, Unauthorized(err)
	}

	return token, nil
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

func authIsEnabled(ctx *gin.Context) bool {
	if ctx == nil {
		return false
	}
	return ctx.GetBool(authContextEnabledKey)
}

func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(authContextEnabledKey, true)

		token := ctx.GetHeader(authHeaderName)
		if token == "" {
			// No token provided; proceed as unauthorized.
			ctx.Next()
			return
		}

		tokenValue, err := authValidateAuthHeader(token)
		if err != nil {
			Unauthorized(err).render(ctx)
			return
		}

		ctx.Set(authContextTokenKey, tokenValue)
		ctx.Next()
	}
}

// authValidateAuthHeader validates the Authorization value `<prefix name> <base64 value>` and returns the corresponding Token.
func authValidateAuthHeader(authHeader string) (Token, error) {
	parsers := map[string]func([]byte) (Token, error){
		"nostr":  authValidateNIP42Token,
		"bearer": authValidateNIP42Token,
		"x.com":  authValidateXcomToken,
		"xcom":   authValidateXcomToken,
	}

	tokenData := strings.SplitN(authHeader, " ", 2)
	if len(tokenData) != 2 {
		return nil, errAuthInvalidFormat
	}

	parser, ok := parsers[strings.ToLower(tokenData[0])]
	if !ok {
		return nil, fmt.Errorf("%w: unknown token prefix %q", errAuthInvalidFormat, tokenData[0])
	}

	jsonData, err := base64.StdEncoding.DecodeString(tokenData[1])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode base64: %v", errAuthInvalidFormat, err)
	}

	return parser(jsonData)
}

func authValidateNIP42Token(jsonToken []byte) (Token, error) {
	var ev model.Event

	err := ev.UnmarshalJSON(jsonToken)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal NIP42 event: %w", errAuthInvalidFormat, err)
	}

	err = authValidateNIP42Event(&ev)
	if err != nil {
		return nil, fmt.Errorf("%q: authorization failed: %w", ev.GetMasterPublicKey(), err)
	}

	return &AuthContextNIP42{
		Event:        &ev,
		MasterPubKey: ev.GetMasterPublicKey(),
	}, nil
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

	attestation, err := model.ParseAttestationTags(attestationEvent.Tags)
	if err != nil {
		return fmt.Errorf("failed to parse attestation tags: %w", err)
	}
	records := attestation.Records
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

func authValidateXcomToken(jsonToken []byte) (Token, error) {
	var userInfo AuthXcomUserInfo

	if err := json.Unmarshal(jsonToken, &userInfo); err != nil {
		return nil, fmt.Errorf("%w: failed to parse JSON: %w", errAuthInvalidFormat, err)
	}

	if userInfo.UserId == "" {
		return nil, fmt.Errorf("%w: missing userId", errAuthXComMissingFields)
	}
	if userInfo.UserHandle == "" {
		return nil, fmt.Errorf("%w: missing userHandle", errAuthXComMissingFields)
	}

	return &AuthContextXcom{
		UserInfo: &userInfo,
	}, nil
}
