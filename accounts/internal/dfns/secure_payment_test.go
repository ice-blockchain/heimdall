// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton/wallet"
)

func TestParseTX(t *testing.T) {
	t.Parallel()
	t.Run("ton", func(t *testing.T) {
		t.Parallel()
		versions := []wallet.VersionConfig{wallet.V4R2, wallet.ConfigV5R1Final{NetworkGlobalID: wallet.TestnetGlobalID}}

		for _, ver := range versions {
			sampleTxBytes, from, to := buildTonTestTx(t, "0QBgUcFayL2fp5S7mEWxjAk6M1KiA1FiNnKPJzLQfLHFBm5k", "0.1", ver)
			var payment transferTransaction
			tx, err := parseTONTransaction(sampleTxBytes, &payment)
			require.NoError(t, err)
			require.Equal(t, transferTransaction{
				ReceiverAddress: to,
				Sender:          "",
				Amount:          "0.1",
				Network: &network{
					Currency: "TON",
					Icon:     "https://ton.org/download/ton_symbol.png",
				},
			}, payment, ver)
			_, _, err = tx.EmbedSignature(bytes.Repeat([]byte{0}, 64), from, false)
			require.NoError(t, err)
		}
		txBuiltWithJS, err := hex.DecodeString("b5ee9c724101040100550001217369676e7369676effffffff7ffffffda001020a0ec3c86d0302030000006842005821edd291a0a1e86754777ab4de1f781e8ca9309b36ec35a9e45cf1834f4ccfa034edce0000000000000000000000000000bcb45537")
		require.NoError(t, err)
		from, err := hex.DecodeString("4eb5da0c1913e9aa672e5c898c8ade1bf12ec93e1264fb0255471003b6093d4e")
		require.NoError(t, err)
		var payment transferTransaction
		tx, err := parseTONTransaction(txBuiltWithJS, &payment)
		require.NoError(t, err)

		require.Equal(t, transferTransaction{
			ReceiverAddress: "UQCwQ9ulI0FD0M6o7vVpvD7wPRlSYTZt2GtTyLnjBp6ZnybT",
			Sender:          "",
			Amount:          "0.111",
			Network: &network{
				Currency: "TON",
				Icon:     "https://ton.org/download/ton_symbol.png",
			},
		}, payment)
		_, signedPayload, err := tx.EmbedSignature(bytes.Repeat([]byte{0}, 64), from, false)
		require.NoError(t, err)
		require.Equal(t, signedPayload.ToBOC(), txBuiltWithJS)
	})
}

func buildTonTestTx(t *testing.T, target, amount string, version wallet.VersionConfig) (tx []byte, fromPubkey ed25519.PublicKey, to string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	api := mustInitTONClient(ctx, "https://ton-blockchain.github.io/testnet-global.config.json")
	pubkey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	w, err := wallet.FromSigner(api, pubkey, version, func(ctx context.Context, cell *cell.Cell) ([]byte, error) {
		return bytes.Repeat([]byte{0}, 64), nil
	})
	require.NoError(t, err)
	toAddr := address.MustParseAddr(target).Bounce(false).Testnet(false)
	transfer, err := w.BuildTransfer(toAddr, tlb.MustFromTON(amount), false, "")
	require.NoError(t, err)
	ext, err := w.BuildExternalMessageForMany(ctx, []*wallet.Message{transfer})
	require.NoError(t, err)

	return ext.Body.ToBOCWithFlags(false), pubkey, toAddr.String()
}
