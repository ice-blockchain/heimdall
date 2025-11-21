// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"encoding/base64"
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
	r.Use(NIP42AuthMiddleware())
	r.GET("/with_auth", RootHandler(func(ctx context.Context, r *Request[RequestTestStruct]) (*Response[string], error) {
		require.NotNil(t, r.Token)
		key := r.Token.GetMasterPublicKey()
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
