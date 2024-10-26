// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"fmt"
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
		sampleTxBytes, _, to := buildTonTestTx(t, "0QBgUcFayL2fp5S7mEWxjAk6M1KiA1FiNnKPJzLQfLHFBm5k", "0.1")
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
		}, payment)
		fmt.Println(tx)
	})
}

func buildTonTestTx(t *testing.T, target, amount string) (tx []byte, from string, to string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	api := mustInitTONClient(ctx, "https://ton-blockchain.github.io/testnet-global.config.json")
	testSeed := wallet.NewSeed()
	w, err := wallet.FromSeed(api, testSeed, wallet.V4R2)
	require.NoError(t, err)
	toAddr := address.MustParseAddr(target).Bounce(false).Testnet(false)
	transfer, err := w.BuildTransfer(toAddr, tlb.MustFromTON(amount), false, "")
	require.NoError(t, err)
	ext, err := w.BuildExternalMessageForMany(ctx, []*wallet.Message{transfer})
	require.NoError(t, err)

	return ext.Body.ToBOCWithFlags(false), w.WalletAddress().String(), toAddr.String()
}
