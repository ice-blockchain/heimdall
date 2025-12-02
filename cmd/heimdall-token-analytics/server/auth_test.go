// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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
	r.Use(AuthMiddleware([]byte("")))
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
	secretKey := []byte("test-secret-key-for-xcom-tokens-123")

	tests := []struct {
		name      string
		userInfo  XComUserInfo
		ttl       time.Duration
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
			ttl:       1 * time.Hour,
			wantError: false,
		},
		{
			name: "expired token",
			userInfo: XComUserInfo{
				UserId:      "987654321",
				UserHandle:  "expireduser",
				DisplayName: "Expired User",
				Verified:    false,
			},
			ttl:       -1 * time.Hour,
			wantError: true,
			errorType: errAuthXComInvalidToken, // JWT library wraps expiration errors
		},
		{
			name: "missing userId",
			userInfo: XComUserInfo{
				UserId:      "", // missing
				UserHandle:  "nouserid",
				DisplayName: "No User ID",
			},
			ttl:       1 * time.Hour,
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
			ttl:       1 * time.Hour,
			wantError: true,
			errorType: errAuthXComMissingFields,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := helperGenerateXComToken(t, tt.userInfo, secretKey, tt.ttl)

			authHeader := xcomAuthScheme + " " + token
			claims, err := authValidateXComToken(authHeader, secretKey)

			if tt.wantError {
				require.Error(t, err)
				if tt.errorType != nil {
					require.ErrorIs(t, err, tt.errorType)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, claims)
				require.Equal(t, tt.userInfo.UserId, claims.XCom.UserId)
				require.Equal(t, tt.userInfo.UserHandle, claims.XCom.UserHandle)
				require.Equal(t, tt.userInfo.DisplayName, claims.XCom.DisplayName)
				require.Equal(t, tt.userInfo.Verified, claims.XCom.Verified)
			}
		})
	}
}

func TestXComAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secretKey := []byte("test-secret-key-for-xcom-tokens-456")

	userInfo := XComUserInfo{
		UserId:      "999888777",
		UserHandle:  "middlewaretest",
		DisplayName: "Middleware Test User",
		Verified:    true,
	}
	token := helperGenerateXComToken(t, userInfo, secretKey, 1*time.Hour)

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
			authHeader:     xcomAuthScheme + " invalid-token",
			expectedStatus: 401,
			checkContext:   false,
		},
		{
			name:           "wrong secret key",
			authHeader:     xcomAuthScheme + " " + helperGenerateXComToken(t, userInfo, []byte("wrong-key"), 1*time.Hour),
			expectedStatus: 401,
			checkContext:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(AuthMiddleware(secretKey))
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
	claims := &XComClaims{
		XCom: XComUserInfo{
			UserId:      "123456",
			UserHandle:  "testhandle",
			DisplayName: "Test Display",
			Verified:    true,
		},
	}

	authCtx := &authContextXCom{Claims: claims}
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
	token := helperGenerateXComToken(t, userInfo, []byte("test-secret-key"), 1*time.Hour)
	require.NotEmpty(t, token)

	fmt.Println("token", token)
}

func helperGenerateXComToken(t *testing.T, userInfo XComUserInfo, secretKey []byte, ttl time.Duration) string {
	t.Helper()

	now := time.Now()
	claims := XComClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    xcomIssuer,
			Subject:   fmt.Sprintf("x.com:%s", userInfo.UserId),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		XCom: userInfo,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	require.NoError(t, err)

	return tokenString
}
