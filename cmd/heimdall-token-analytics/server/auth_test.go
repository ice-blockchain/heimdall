// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/go/src/net/http"
	"github.com/ice-blockchain/subzero/model"
)

func helperMustGetPubKey(t *testing.T, privateKey string) string {
	t.Helper()

	key, err := model.GetPublicKey(privateKey)
	require.NoError(t, err)

	return key
}

func helperCreateAuthEventNIP42(t *testing.T, userPrivate, masterPrivate string) *model.Event {
	t.Helper()

	var attestation model.Event
	attestation.Kind = model.CustomIONKindAttestation
	attestation.CreatedAt = nostr.Now()
	attestation.Tags = model.Tags{
		{model.TagAttestationName, helperMustGetPubKey(t, userPrivate), "", model.CustomIONAttestationKindActive + ":" + attestation.CreatedAt.Add(-time.Hour).String()},
	}
	require.NoError(t, attestation.SignWithAlg(masterPrivate, model.SignAlgEDDSA, model.KeyAlgCurve25519))

	var ev model.Event
	ev.Kind = nostr.KindClientAuthentication
	ev.CreatedAt = nostr.Now()
	ev.Tags = model.Tags{
		{"attestation", attestation.String()},
		{model.CustomIONTagOnBehalfOf, helperMustGetPubKey(t, masterPrivate)},
	}
	require.NoError(t, ev.SignWithAlg(userPrivate, model.SignAlgEDDSA, model.KeyAlgCurve25519))

	return &ev
}

func helperCreateAuthTokenNIP42(t *testing.T, userPrivate, masterPrivate string) string {
	t.Helper()

	ev := helperCreateAuthEventNIP42(t, userPrivate, masterPrivate)
	return `Nostr ` + base64.StdEncoding.EncodeToString([]byte(ev.String()))
}

func TestAuthNIP42(t *testing.T) {
	t.Parallel()

	type RequestTestStruct struct {
		Foo string `form:"foo"`
	}

	type RequestTestStructNoAuth struct {
		NoAuthRequired
		RequestTestStruct
	}

	r := helperNewRouter(t)
	r.Use(AuthMiddleware())
	r.GET("/with_auth", RootHandler(func(ctx context.Context, r *Request[RequestTestStruct]) (*Response[string], error) {
		require.NotNil(t, r.Token)
		nostrToken, ok := r.Token.(NostrToken)
		require.True(t, ok, "Expected NostrToken")
		key := nostrToken.GetMasterPublicKey()
		require.NotEmpty(t, key)
		return OK(&key), nil
	}))
	r.GET("/no_auth", RootHandler(func(ctx context.Context, r *Request[RequestTestStructNoAuth]) (*Response[string], error) {
		var resp = "OK"
		return OK(&resp), nil
	}))
	r.GET("/healthz", func(c *gin.Context) {
		NoContent().render(c)
	})

	t.Run("Success with auth", func(t *testing.T) {
		userKey := model.GeneratePrivateKey()
		masterKey := model.GeneratePrivateKey()
		token := helperCreateAuthTokenNIP42(t, userKey, masterKey)

		resp := helperDoRequestWithAuth[string](t, r, token, http.MethodGet, "/with_auth?foo=bar", http.NoBody)
		require.Equal(t, http.StatusOK, resp.Code)
		require.NotNil(t, resp.Data)
		require.Equal(t, helperMustGetPubKey(t, masterKey), *resp.Data)
	})
	t.Run("Forbidden missing token", func(t *testing.T) {
		resp := helperDoRequest[ResponseErrorBody](t, r, http.MethodGet, "/with_auth?foo=bar", http.NoBody)
		require.Equal(t, http.StatusForbidden, resp.Code)
	})
	t.Run("Unauthorized invalid token", func(t *testing.T) {
		resp := helperDoRequestWithAuth[ResponseErrorBody](t, r, "someinvalidtoken", http.MethodGet, "/with_auth?foo=bar", http.NoBody)
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	})
	t.Run("Success no auth required", func(t *testing.T) {
		resp := helperDoRequest[string](t, r, http.MethodGet, "/no_auth", http.NoBody)
		require.Equal(t, http.StatusOK, resp.Code)
		require.NotNil(t, resp.Data)
	})
	t.Run("Generic handler unaffected", func(t *testing.T) {
		resp := helperDoRequest[string](t, r, http.MethodGet, "/healthz", http.NoBody)
		require.Equal(t, http.StatusNoContent, resp.Code)
	})
}

func TestXComTokenValidation(t *testing.T) {
	tests := []struct {
		name      string
		userInfo  XComUserInfo
		wantError bool
		errorType error
	}{
		{
			name: "valid token",
			userInfo: XComUserInfo{
				UserId:      "123456789",
				UserHandle:  "testuser",
				DisplayName: "Test User",
				Verified:    true,
			},
			wantError: false,
		},
		{
			name: "missing userId",
			userInfo: XComUserInfo{
				UserId:      "", // missing
				UserHandle:  "nouserid",
				DisplayName: "No User ID",
			},
			wantError: true,
			errorType: errAuthXComMissingFields,
		},
		{
			name: "missing userHandle",
			userInfo: XComUserInfo{
				UserId:      "111222333",
				UserHandle:  "",
				DisplayName: "No Handle",
			},
			wantError: true,
			errorType: errAuthXComMissingFields,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := helperGenerateXComToken(t, tt.userInfo)

			authHeader := xcomAuthScheme + " " + token
			userInfo, err := authValidateXComToken(authHeader)

			if tt.wantError {
				require.Error(t, err)
				if tt.errorType != nil {
					require.ErrorIs(t, err, tt.errorType)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, userInfo)
				require.Equal(t, tt.userInfo.UserId, userInfo.UserId)
				require.Equal(t, tt.userInfo.UserHandle, userInfo.UserHandle)
				require.Equal(t, tt.userInfo.DisplayName, userInfo.DisplayName)
				require.Equal(t, tt.userInfo.Verified, userInfo.Verified)
			}
		})
	}
}

func TestXComAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	userInfo := XComUserInfo{
		UserId:      "999888777",
		UserHandle:  "middlewaretest",
		DisplayName: "Middleware Test User",
		Verified:    true,
	}
	token := helperGenerateXComToken(t, userInfo)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		checkContext   bool
	}{
		{
			name:           "valid X.com token",
			authHeader:     xcomAuthScheme + " " + token,
			expectedStatus: 200,
			checkContext:   true,
		},
		{
			name:           "no auth header",
			authHeader:     "",
			expectedStatus: 200,
			checkContext:   false,
		},
		{
			name:           "invalid token format",
			authHeader:     xcomAuthScheme + " invalid-not-base64!!!",
			expectedStatus: 401,
			checkContext:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(AuthMiddleware())
			router.GET("/test", func(ctx *gin.Context) {
				if tt.checkContext {
					tokenCtx := authGetToken(ctx)
					require.NotNil(t, tokenCtx)

					xcomToken, ok := tokenCtx.(XComToken)
					require.True(t, ok, "Expected XComToken")
					require.NotNil(t, xcomToken)
					require.Equal(t, userInfo.UserId, xcomToken.GetUserId())
					require.Equal(t, userInfo.UserHandle, xcomToken.GetUserHandle())
					require.Equal(t, userInfo.DisplayName, xcomToken.GetDisplayName())
					require.Equal(t, userInfo.Verified, xcomToken.IsVerified())
				}
				ctx.Status(200)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestXComTokenInterfaces(t *testing.T) {
	userInfo := &XComUserInfo{
		UserId:      "123456",
		UserHandle:  "testhandle",
		DisplayName: "Test Display",
		Verified:    true,
	}

	authCtx := &authContextXCom{UserInfo: userInfo}
	var xcomToken XComToken = authCtx
	require.Equal(t, "123456", xcomToken.GetUserId())
	require.Equal(t, "testhandle", xcomToken.GetUserHandle())
	require.Equal(t, "Test Display", xcomToken.GetDisplayName())
	require.True(t, xcomToken.IsVerified())
}

func TestGenerateXComToken(t *testing.T) {
	userInfo := XComUserInfo{
		UserId:      "123456789",
		UserHandle:  "testuser",
		DisplayName: "Test User",
		Verified:    true,
	}
	token := helperGenerateXComToken(t, userInfo)
	require.NotEmpty(t, token)

	t.Logf("Generated X.com token: %s", token)
}

func helperGenerateXComToken(t *testing.T, userInfo XComUserInfo) string {
	t.Helper()

	jsonData, err := json.Marshal(userInfo)
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(jsonData)
}
