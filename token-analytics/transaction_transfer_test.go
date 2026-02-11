// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	bondingcurvefixture "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve/fixture"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestOnTransfer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
	mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC))
	defer ta.Close()

	t.Run("processes_p2p_transfer_successfully", func(t *testing.T) {
		tokenContractAddr := strings.ToLower("0x8dC5aa6777F9A6128f8775f93be4bA1a503723AE")
		tokenExternalAddr := "0:test_creator_pubkey_transfer:"
		creatorPubkey := "test_creator_pubkey_transfer"

		helperInsertTestUser(t, ctx, db, creatorPubkey, "test_user", "Test User", "0xSomeAddress", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "TTOKEN", TokenTypeProfile, creatorPubkey, "1000000000000000000000", 0, 0.1, 0, PlatformGroupIonConnect)

		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, "0x0000000000000000000000000000000000000000000000000000000000000001", baseToken)

		senderAddr := strings.ToLower("0xd38D7cDab8802A4Dc5730f9Dfd24464545BB88aC")
		senderExternalAddr := "0:sender_pubkey:"
		receiverAddr := strings.ToLower("0x70E06D947F05A6324B12BfE31e2c693a4e369c5E")
		receiverExternalAddr := "0:receiver_pubkey:"

		helperInsertTestUser(t, ctx, db, "sender_pubkey", "sender", "Sender", senderAddr, false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "receiver_pubkey", "receiver", "Receiver", receiverAddr, false, PlatformGroupIonConnect)

		// Sender has 150 tokens
		helperInsertUserPosition(t, ctx, db, senderAddr, tokenContractAddr, tokenExternalAddr, senderExternalAddr, "150000000000000000000")

		// Receiver has 0 tokens
		helperInsertUserPosition(t, ctx, db, receiverAddr, tokenContractAddr, tokenExternalAddr, receiverExternalAddr, "0")

		senderInitialBalance := helperGetUserPosition(t, ctx, db, senderAddr, tokenContractAddr)
		receiverInitialBalance := helperGetUserPosition(t, ctx, db, receiverAddr, tokenContractAddr)

		require.NotNil(t, senderInitialBalance, "Sender should have initial position")
		require.NotNil(t, receiverInitialBalance, "Receiver should have initial position")
		require.Equal(t, "150000000000000000000", senderInitialBalance.Amount, "Sender initial balance should be 150 tokens")
		require.Equal(t, "0", receiverInitialBalance.Amount, "Receiver initial balance should be 0 tokens")

		// Sender transfers 75 tokens to receiver
		transferAmount := new(big.Int)
		transferAmount.SetString("75000000000000000000", 10) // 75 tokens (18 decimals)
		tx := &txEvent{
			TransactionHash: "0x35c600124ae61ba86e9c85b679bd4c40c9bb30274f59d698593a52827f6d2746",
			Logs:            make(txEventLogs, 0),
		}

		ev := &bondingcurve.LogTransfer{
			TokenAddress: common.HexToAddress(tokenContractAddr),
			From:         common.HexToAddress(senderAddr),
			To:           common.HexToAddress(receiverAddr),
			Value:        transferAmount,
		}

		// After transfer: Sender 150 - 75 = 75, Receiver 0 + 75 = 75
		// Mock returns 75 tokens for both (simulating actual on-chain balance)
		expectedBalance := new(big.Int)
		expectedBalance.SetString("75000000000000000000", 10) // 75 tokens
		mockBackend.SetBalanceOfResponse(expectedBalance)

		require.NoError(t, ta.onTransfer(ctx, tx, ev))

		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		senderFinalBalance := helperGetUserPosition(t, ctx, db, senderAddr, tokenContractAddr)
		receiverFinalBalance := helperGetUserPosition(t, ctx, db, receiverAddr, tokenContractAddr)

		require.NotNil(t, senderFinalBalance, "Sender should still have position after transfer")
		require.NotNil(t, receiverFinalBalance, "Receiver should still have position after transfer")

		require.Equal(t, "75000000000000000000", senderFinalBalance.Amount,
			"Sender balance should be 75 tokens (150 - 75)")
		require.Equal(t, "75000000000000000000", receiverFinalBalance.Amount,
			"Receiver balance should be 75 tokens (0 + 75)")
	})

	t.Run("skips_transfer_in_swap_transaction", func(t *testing.T) {
		tokenContractAddr := strings.ToLower("0xABCDEF1234567890ABCDEF1234567890ABCDEF12")
		tokenExternalAddr := "0:swap_creator_pubkey:"
		creatorPubkey := "swap_creator_pubkey"
		userAddr := strings.ToLower("0xSwapAddr000000000000000000000000000000")
		userExternalAddr := "0:swap_user_pubkey:"
		receiverAddr := strings.ToLower(ta.cfg.BondingCurve.SmartContractAddress)

		helperInsertTestUser(t, ctx, db, creatorPubkey, "swap_user", "Swap User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "swap_user_pubkey", "swapper", "Swapper", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "SWAP", TokenTypeProfile, creatorPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)

		helperInsertUserPosition(t, ctx, db, userAddr, tokenContractAddr, tokenExternalAddr, userExternalAddr, "100000000000000000000")

		initialPosition := helperGetUserPosition(t, ctx, db, userAddr, tokenContractAddr)
		require.NotNil(t, initialPosition)
		require.Equal(t, "100000000000000000000", initialPosition.Amount)

		// Create a transaction that contains both Transfer and TokenSwapped events
		swapTxEvt := &txEvent{
			TransactionHash: "0xswap_tx_with_transfer",
			Logs: txEventLogs{
				// Transfer event (from user to bonding curve)
				{
					"topic0":  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // Transfer
					"topic1":  "0x000000000000000000000000" + strings.TrimPrefix(userAddr, "0x"),
					"topic2":  "0x000000000000000000000000" + strings.TrimPrefix(receiverAddr, "0x"),
					"data":    "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000", // 1 token
					"address": tokenContractAddr,
				},
				// TokenSwapped event
				{
					"topic0":  bondingcurve.EventSwappedSignature, // Event signature
					"topic1":  "0x000000000000000000000000" + strings.TrimPrefix(userAddr, "0x"),
					"topic2":  "0x1111111111111111111111111111111111111111111111111111111111111111", // pair_id
					"data":    "0x0000000000000000000000000000000000000000000000000000000000000000", // direction, amounts, etc
					"address": ta.cfg.BondingCurve.SmartContractAddress,
				},
			},
		}

		isSwap := ta.isSwapTransaction(swapTxEvt)
		require.True(t, isSwap, "Transaction with TokenSwapped event should return true")

		ev := &bondingcurve.LogTransfer{
			TokenAddress: common.HexToAddress(tokenContractAddr),
			From:         common.HexToAddress(userAddr),
			To:           common.HexToAddress(receiverAddr),
			Value:        big.NewInt(1000000000000000000), // 1 token
		}

		type jobCount struct {
			Count int64 `db:"count"`
		}
		before, err := storage.Get[jobCount](ctx, ta.ingestedDataDB, `SELECT COUNT(*) as count FROM river_job WHERE kind = 'balance_update'`)
		require.NoError(t, err)

		err = ta.onTransfer(ctx, swapTxEvt, ev)
		require.NoError(t, err)

		after, err := storage.Get[jobCount](ctx, ta.ingestedDataDB, `SELECT COUNT(*) as count FROM river_job WHERE kind = 'balance_update'`)
		require.NoError(t, err)
		require.Equal(t, before.Count, after.Count, "No new jobs should be created for transfer in swap transaction")

		finalPosition := helperGetUserPosition(t, ctx, db, userAddr, tokenContractAddr)
		require.NotNil(t, finalPosition)
		require.Equal(t, "100000000000000000000", finalPosition.Amount, "Position should remain unchanged")
	})

	t.Run("skips_transfer_in_uniswap_swap_transaction", func(t *testing.T) {
		tokenContractAddr := strings.ToLower("0xUNISWAP123456789UNISWAP123456789UNISW12")
		tokenExternalAddr := "0:uniswap_creator_pubkey:"
		creatorPubkey := "uniswap_creator_pubkey"
		userAddr := strings.ToLower("0xUniswapAddr000000000000000000000000000")
		userExternalAddr := "0:uniswap_user_pubkey:"
		poolAddr := strings.ToLower("0xPoolAddr000000000000000000000000000000")

		helperInsertTestUser(t, ctx, db, creatorPubkey, "uniswap_user", "Uniswap User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "uniswap_user_pubkey", "uniswapper", "Uniswapper", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "USWAP", TokenTypeProfile, creatorPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)

		helperInsertUserPosition(t, ctx, db, userAddr, tokenContractAddr, tokenExternalAddr, userExternalAddr, "100000000000000000000")

		initialPosition := helperGetUserPosition(t, ctx, db, userAddr, tokenContractAddr)
		require.NotNil(t, initialPosition)
		require.Equal(t, "100000000000000000000", initialPosition.Amount)

		uniswapSwapTxEvt := &txEvent{
			TransactionHash: "0xuniswap_swap_tx_with_transfer",
			Logs: txEventLogs{
				// Transfer event (from user to pool)
				{
					"topic0":  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // Transfer
					"topic1":  "0x000000000000000000000000" + strings.TrimPrefix(userAddr, "0x"),
					"topic2":  "0x000000000000000000000000" + strings.TrimPrefix(poolAddr, "0x"),
					"data":    "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000", // 1 token
					"address": tokenContractAddr,
				},
				// Uniswap Swap event (Swap(address,address,int256,int256,uint160,uint128,int24))
				{
					"topic0":  bondingcurve.EventUniswapSwappedSignature, // Uniswap Swap event signature
					"topic1":  "0x000000000000000000000000" + strings.TrimPrefix(userAddr, "0x"),
					"topic2":  "0x000000000000000000000000" + strings.TrimPrefix(userAddr, "0x"),
					"data":    "0x0000000000000000000000000000000000000000000000000000000000000000", // amounts, sqrtPriceX96, liquidity, tick
					"address": poolAddr,
				},
			},
		}

		isSwap := ta.isSwapTransaction(uniswapSwapTxEvt)
		require.True(t, isSwap, "Transaction with Uniswap Swap event should return true")

		ev := &bondingcurve.LogTransfer{
			TokenAddress: common.HexToAddress(tokenContractAddr),
			From:         common.HexToAddress(userAddr),
			To:           common.HexToAddress(poolAddr),
			Value:        big.NewInt(1000000000000000000), // 1 token
		}

		type jobCount struct {
			Count int64 `db:"count"`
		}
		before, err := storage.Get[jobCount](ctx, ta.ingestedDataDB, `SELECT COUNT(*) as count FROM river_job WHERE kind = 'balance_update'`)
		require.NoError(t, err)

		err = ta.onTransfer(ctx, uniswapSwapTxEvt, ev)
		require.NoError(t, err)

		after, err := storage.Get[jobCount](ctx, ta.ingestedDataDB, `SELECT COUNT(*) as count FROM river_job WHERE kind = 'balance_update'`)
		require.NoError(t, err)
		require.Equal(t, before.Count, after.Count, "No new jobs should be created for transfer in Uniswap swap transaction")

		finalPosition := helperGetUserPosition(t, ctx, db, userAddr, tokenContractAddr)
		require.NotNil(t, finalPosition)
		require.Equal(t, "100000000000000000000", finalPosition.Amount, "Position should remain unchanged")
	})

	t.Run("skips_burn_transfers", func(t *testing.T) {
		tokenContractAddr := strings.ToLower("0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
		tokenExternalAddr := "0:burn_creator:"
		creatorPubkey := "burn_creator"

		helperInsertTestUser(t, ctx, db, creatorPubkey, "burn_user", "Burn User", "0xBurnAddr0000000000000000000000000000000", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "BURN", TokenTypeProfile, creatorPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)

		txFromBurnAddr := &txEvent{
			TransactionHash: "0xfrom_burn_address_transaction",
			Logs:            make(txEventLogs, 0),
		}

		evFromBurnAddr := &bondingcurve.LogTransfer{
			TokenAddress: common.HexToAddress(tokenContractAddr),
			From:         common.HexToAddress(ta.cfg.BondingCurve.BurnAddress), // 0x0000000000000000000000000000000000696f6e
			To:           common.HexToAddress("0x3333333333333333333333333333333333333333"),
			Value:        big.NewInt(1000000000000000000),
		}

		require.NoError(t, ta.onTransfer(ctx, txFromBurnAddr, evFromBurnAddr))

		txFromZeroAddr := &txEvent{
			TransactionHash: "0xfrom_zero_address_transaction",
			Logs:            make(txEventLogs, 0),
		}

		evFromZeroAddr := &bondingcurve.LogTransfer{
			TokenAddress: common.HexToAddress(tokenContractAddr),
			From:         common.HexToAddress("0x0000000000000000000000000000000000000000"),
			To:           common.HexToAddress("0x3333333333333333333333333333333333333333"),
			Value:        big.NewInt(1000000000000000000),
		}
		require.NoError(t, ta.onTransfer(ctx, txFromZeroAddr, evFromZeroAddr))
	})
	t.Run("burn transfers updates balances for sender", func(t *testing.T) {
		tokenContractAddr := strings.ToLower("0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
		tokenExternalAddr := "0:burn_creator:"
		creatorPubkey := "burn_creator"

		helperInsertTestUser(t, ctx, db, creatorPubkey, "burn_user", "Burn User", "0xBurnAddr0000000000000000000000000000000", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "BURN", TokenTypeProfile, creatorPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)

		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, "0x0000000000000000000000000000000000000000000000000000000000000001", baseToken)

		senderAddr := strings.ToLower("0xd38D7cDab8802A4Dc5730f9Dfd24464545BB88aC")
		senderExternalAddr := "0:sender_pubkey:"

		helperInsertTestUser(t, ctx, db, "sender_pubkey", "sender", "Sender", senderAddr, false, PlatformGroupIonConnect)
		// Sender has 150 tokens
		helperInsertUserPosition(t, ctx, db, senderAddr, tokenContractAddr, tokenExternalAddr, senderExternalAddr, "150000000000000000000")

		senderInitialBalance := helperGetUserPosition(t, ctx, db, senderAddr, tokenContractAddr)

		require.NotNil(t, senderInitialBalance, "Sender should have initial position")
		require.Equal(t, "150000000000000000000", senderInitialBalance.Amount, "Sender initial balance should be 150 tokens")

		// Sender transfers 75 tokens to burned
		transferAmount := new(big.Int)
		transferAmount.SetString("75000000000000000000", 10) // 75 tokens (18 decimals)
		tx := &txEvent{
			TransactionHash: "0x35c600124ae61ba86e9c85b679bd4c40c9bb30274f59d698593a52827f6d2746",
			Logs:            make(txEventLogs, 0),
		}

		ev := &bondingcurve.LogTransfer{
			TokenAddress: common.HexToAddress(tokenContractAddr),
			From:         common.HexToAddress(senderAddr),
			To:           common.HexToAddress(ta.cfg.BondingCurve.BurnAddress),
			Value:        transferAmount,
		}

		expectedBalance := new(big.Int)
		expectedBalance.SetString("75000000000000000000", 10) // 75 tokens
		mockBackend.SetBalanceOfResponse(expectedBalance)

		require.NoError(t, ta.onTransfer(ctx, tx, ev))

		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		senderFinalBalance := helperGetUserPosition(t, ctx, db, senderAddr, tokenContractAddr)

		require.NotNil(t, senderFinalBalance, "Sender should still have position after transfer")

		require.Equal(t, "75000000000000000000", senderFinalBalance.Amount,
			"Sender balance should be 75 tokens (150 - 75)")

		// Sender transfers 75 tokens to zero address
		transferAmount.SetString("75000000000000000000", 10) // 75 tokens (18 decimals)
		tx = &txEvent{
			TransactionHash: "0x37c600124ae61ba86e9c85b679bd4c40c9bb30274f59d698593a52827f6d2749",
			Logs:            make(txEventLogs, 0),
		}

		ev = &bondingcurve.LogTransfer{
			TokenAddress: common.HexToAddress(tokenContractAddr),
			From:         common.HexToAddress(senderAddr),
			To:           common.HexToAddress("0x0000000000000000000000000000000000000000"),
			Value:        transferAmount,
		}

		expectedBalance.SetString("0", 10)
		mockBackend.SetBalanceOfResponse(expectedBalance)

		require.NoError(t, ta.onTransfer(ctx, tx, ev))

		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		senderFinalBalance = helperGetUserPosition(t, ctx, db, senderAddr, tokenContractAddr)

		require.NotNil(t, senderFinalBalance, "Sender should have zero position after transfer as all money is gone")

		require.Equal(t, "0", senderFinalBalance.Amount,
			"Sender balance should be 0 tokens (150 - 75 - 75)")
	})
	t.Run("skips_unknown_tokens", func(t *testing.T) {
		tx := &txEvent{
			TransactionHash: "0xunknown_token_transfer",
			Logs:            make(txEventLogs, 0),
		}

		ev := &bondingcurve.LogTransfer{
			TokenAddress: common.HexToAddress("0x9999999999999999999999999999999999999999"), // Unknown token
			From:         common.HexToAddress("0x4444444444444444444444444444444444444444"),
			To:           common.HexToAddress("0x5555555555555555555555555555555555555555"),
			Value:        big.NewInt(1000000000000000000),
		}

		err := ta.onTransfer(ctx, tx, ev)
		require.NoError(t, err)
	})
	t.Run("burned transfers are saved as burned fees in trigger", func(t *testing.T) {
		tokenContractAddr := strings.ToLower("0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
		tokenExternalAddr := "0:burn_creator:"
		creatorPubkey := "burn_creator"

		helperInsertTestUser(t, ctx, db, creatorPubkey, "burn_user", "Burn User", "0xBurnAddr0000000000000000000000000000000", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "BURN", TokenTypeProfile, creatorPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)

		blockTimestamp := "2024-01-01 12:00:00"
		topics := []string{
			"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // FeeTransfer
			"0x000000000000000000000000d38D7cDab8802A4Dc5730f9Dfd24464545BB88aC", // from
			"0x0000000000000000000000000000000000000000000000000000000000000000", // to (zero)
		}
		data := "0x" +
			"0000000000000000000000000000000000000000000000008ac7230489e80000" // 10000000000000000000

		_, err := storage.Exec(ctx, db, `
			SELECT process_erc20_transfer($4,$2, $3, $1);
		`,
			blockTimestamp,
			topics,
			data,
			tokenContractAddr,
		)
		require.NoError(t, err)

		type feeResult struct {
			TokenExternalAddress string  `db:"token_external_address"`
			RecipientBscAddress  string  `db:"recipient_bsc_address"`
			Type                 string  `db:"fee_type"`
			Amount               float64 `db:"amount"`
		}
		res, err := storage.Get[feeResult](ctx, db, `
			SELECT token_external_address, recipient_bsc_address, fee_type, amount
			FROM fees_transferred
			WHERE token_external_address = $1 AND recipient_bsc_address = $2
		`, tokenExternalAddr, "0x0000000000000000000000000000000000696f6e")
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, "0x0000000000000000000000000000000000696f6e", res.RecipientBscAddress)
		require.Equal(t, feeDestinationBurn, res.Type)
		require.Equal(t, float64(10000000000000000000), res.Amount)
	})

}
