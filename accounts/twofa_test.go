// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"encoding/base64"
	"testing"
	stdlibtime "time"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/time"
)

//nolint:funlen // .
func TestVerifySignature(t *testing.T) {
	t.Parallel()
	a := accounts{cfg: &config{UserSignatureExpiration: 1 * stdlibtime.Hour}}
	now := time.New(stdlibtime.Unix(1728895576, 0))
	signature := "aUiUYaH6I4zMSWghSDH6ho5CUimI7WTv+7QcXIG4fHJw4zcUkrtyk9Z+gkQ/oHSil8ZP1KPPLMyQuvJljGJMCA=="
	validSignatureHeader := base64.StdEncoding.EncodeToString([]byte(signature + ":1728895575:us-3968b-s8lt6-9t3an2s8d2up73oj"))
	t.Run("valid", func(t *testing.T) {
		t.Skip("FIXME")
		require.NoError(t, a.verifyUserSignature(
			validSignatureHeader,
			now, &user{ID: "us-3968b-s8lt6-9t3an2s8d2up73oj", MasterPubKey: "aac1a8f53c5a86a8d8f46569c31710530a5bcc809c5f610f97b6da3afb8ad2d7"}))
	})
	t.Run("not a base64", func(t *testing.T) {
		t.Parallel()
		require.ErrorIs(t, a.verifyUserSignature(
			"",
			now, &user{ID: "us-3968b-s8lt6-9t3an2s8d2up73oj", MasterPubKey: "aac1a8f53c5a86a8d8f46569c31710530a5bcc809c5f610f97b6da3afb8ad2d7"}),
			ErrInvalidUserSignature)
	})
	t.Run("messed content", func(t *testing.T) {
		t.Parallel()
		require.ErrorIs(t, a.verifyUserSignature(
			"Ojo=",
			now, &user{ID: "us-3968b-s8lt6-9t3an2s8d2up73oj", MasterPubKey: "aac1a8f53c5a86a8d8f46569c31710530a5bcc809c5f610f97b6da3afb8ad2d7"}),
			ErrInvalidUserSignature)
		require.ErrorIs(t, a.verifyUserSignature(
			"dGVzdA==",
			now, &user{ID: "us-3968b-s8lt6-9t3an2s8d2up73oj", MasterPubKey: "aac1a8f53c5a86a8d8f46569c31710530a5bcc809c5f610f97b6da3afb8ad2d7"}),
			ErrInvalidUserSignature)
	})
	t.Run("invalid user or signature", func(t *testing.T) {
		t.Parallel()
		require.ErrorIs(t, a.verifyUserSignature(
			validSignatureHeader,
			now, &user{ID: "user", MasterPubKey: "aac1a8f53c5a86a8d8f46569c31710530a5bcc809c5f610f97b6da3afb8ad2d7"}),
			ErrInvalidUserSignature)
		require.ErrorIs(t, a.verifyUserSignature(
			validSignatureHeader,
			now, &user{ID: "us-3968b-s8lt6-9t3an2s8d2up73oj", MasterPubKey: "801E5FE5D9DB244EFC865AC23BE3949BBE71119AB2551A83C36500E71C4609F8"}),
			ErrInvalidUserSignature)
		require.ErrorIs(t, a.verifyUserSignature(
			base64.StdEncoding.EncodeToString([]byte("someinvalidsignature"+":1728895575:us-3968b-s8lt6-9t3an2s8d2up73oj")),
			now, &user{ID: "us-3968b-s8lt6-9t3an2s8d2up73oj", MasterPubKey: "aac1a8f53c5a86a8d8f46569c31710530a5bcc809c5f610f97b6da3afb8ad2d7"}),
			ErrInvalidUserSignature)
	})
	t.Run("expired or not valid yet", func(t *testing.T) {
		t.Parallel()
		before := time.New(now.Add(-2 * stdlibtime.Second))
		require.ErrorIs(t, a.verifyUserSignature(
			validSignatureHeader,
			before, &user{ID: "user", MasterPubKey: "aac1a8f53c5a86a8d8f46569c31710530a5bcc809c5f610f97b6da3afb8ad2d7"}),
			ErrInvalidUserSignature)
		expired := time.New(now.Add(2 * stdlibtime.Hour))
		require.ErrorIs(t, a.verifyUserSignature(
			validSignatureHeader,
			expired, &user{ID: "user", MasterPubKey: "aac1a8f53c5a86a8d8f46569c31710530a5bcc809c5f610f97b6da3afb8ad2d7"}),
			ErrInvalidUserSignature)
	})
}
