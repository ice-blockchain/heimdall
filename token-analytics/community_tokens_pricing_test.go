// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve/fixture"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestGetTokenPricing(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, connString, dbCleanup := helperCreateDBWithConnString(t)
	defer dbCleanup()

	ta := helperNewForTestWithConnString(t, db, connString, WithoutQuestDB())

	mockBackend, bondingCurveAddr, bondingCurveCaller := fixture.SetupMockedBondingCurveBackend(t, &fixture.MockBackendConfig{
		BuyPrice:  big.NewInt(950000000000000000),  // 0.95 tokens
		SellPrice: big.NewInt(1050000000000000000), // 1.05 tokens
	})
	defer mockBackend.Close()
	regularCurve := fixture.CreateMockedBondingCurveInstance(bondingCurveCaller, bondingCurveAddr)
	ta.bondingCurve = regularCurve
	ta.cfg.BondingCurve.CreateTokenDefaults = map[string]createTokenDefaults{}
	ta.cfg.BondingCurve.CreateTokenDefaults["post"] = createTokenDefaults{
		InitialPrice:           "10000",
		FinalPrice:             "100000",
		EmissionVolume:         "1000000000000000000000",
		BondingCurveAlgAddress: "0x000000000000000000000000000000000000dead",
		FeeSponsorAddress:      "0x000000000000000000000000000000000000dead",
		FeeSponsorId:           "post",
	}
	ta.cfg.BondingCurve.CreateTokenDefaults["profile"] = createTokenDefaults{
		InitialPrice:           "1000000",
		FinalPrice:             "100000000",
		EmissionVolume:         "1000000000000000000000",
		BondingCurveAlgAddress: "0x000000000000000000000000000000000000dead",
		FeeSponsorAddress:      "0x000000000000000000000000000000000000dead",
		FeeSponsorId:           "profile",
	}
	ionPrice := 0.1
	bnbPrice := 600.0
	ta.ionPriceUSD.Store(&ionPrice)
	ta.bnbPriceUSD.Store(&bnbPrice)

	helperInsertBaseTokenPrice(t, ctx, db, ta.cfg.IONTokenAddress, "ION", ionPrice)
	helperInsertBaseTokenPrice(t, ctx, db, "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "BNB", bnbPrice)

	// ========== X_COM Tests ==========
	t.Run("buy_xcom_post_token_first_swap_with_fat_address", func(t *testing.T) {
		xcomPostID := "999888777666"
		postContractAddr := "0x3333333333333333333333333333333333333333"

		fatAddressBytes := buildFatAddressV2Single(
			"X Post Token", "XPOST", xcomPostID, 'y',
			common.Address{}, common.Address{},
		)
		fatAddressHex := "0x" + common.Bytes2Hex(fatAddressBytes)

		amount := big.NewInt(1000000000000000000) // 1 ION
		p, err := ta.GetTokenPricing(ctx, fatAddressHex, TradeTypeBuy, amount, nil, nil, 0)
		require.NoError(t, err)
		tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
		require.Equal(t, big.NewInt(950000000000000000).String(), tokensOut.String(), "Should return 0.95 tokens")
		require.InDelta(t, 0.1, tokenPriceUSD, 0.0001, "Should be $0.1")
		require.Greater(t, tokensBNB.Int64(), int64(0), "Should have BNB value")
		require.Equal(t, ionPrice, ionPriceReturned)
		require.Equal(t, bnbPrice, bnbPriceReturned)
		require.Equal(t, "100000", p.ContentTokenParams.FinalPrice)
		require.Equal(t, "10000", p.ContentTokenParams.InitialPrice)
		require.Equal(t, "1000000000000000000000", p.ContentTokenParams.EmissionVolume)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.ContentTokenParams.BondingCurveAlgAddress)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.FeeSponsorAddress)
		require.Equal(t, "post", p.FeeSponsorId)

		// Insert token for 1+ swap test
		helperInsertTestUser(t, ctx, db, xcomPostID, "xcom_user", "X User", "", true, PlatformGroupXCom)
		helperInsertTestToken(t, ctx, db, postContractAddr, xcomPostID, "XPOST", "post", xcomPostID, "1000000000000000000000", 0, 0, 0, PlatformGroupXCom)
		_, err = storage.Exec(ctx, db, `UPDATE tokens SET base_token = $1 WHERE contract_address = $2`, ta.cfg.IONTokenAddress, postContractAddr)
		require.NoError(t, err)
	})

	t.Run("buy_xcom_post_token_1plus_swap", func(t *testing.T) {
		// Token already exists from previous test
		xcomPostID := "999888777666"

		amount := big.NewInt(1000000000000000000) // 1 ION
		p, err := ta.GetTokenPricing(ctx, xcomPostID, TradeTypeBuy, amount, nil, nil, 0)
		require.NoError(t, err)
		tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
		require.Equal(t, big.NewInt(950000000000000000).String(), tokensOut.String())
		require.InDelta(t, 0.1, tokenPriceUSD, 0.0001)
		require.Greater(t, tokensBNB.Int64(), int64(0))
		require.Equal(t, ionPrice, ionPriceReturned)
		require.Equal(t, bnbPrice, bnbPriceReturned)
		require.Equal(t, "100000", p.ContentTokenParams.FinalPrice)
		require.Equal(t, "10000", p.ContentTokenParams.InitialPrice)
		require.Equal(t, "1000000000000000000000", p.ContentTokenParams.EmissionVolume)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.ContentTokenParams.BondingCurveAlgAddress)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.FeeSponsorAddress)
		require.Equal(t, "post", p.FeeSponsorId)
	})

	t.Run("sell_xcom_post_token_1plus_swap", func(t *testing.T) {
		xcomPostID := "999888777666"

		amount := big.NewInt(1000000000000000000) // 1 post token
		p, err := ta.GetTokenPricing(ctx, xcomPostID, TradeTypeSell, amount, nil, nil, 0)
		tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
		require.NoError(t, err)
		require.Equal(t, big.NewInt(1050000000000000000).String(), tokensOut.String(), "Should return 1.05 ION")
		require.InDelta(t, 0.105, tokenPriceUSD, 0.0001, "Should be $0.105 (1.05 spent * 0.1)")
		require.Greater(t, tokensBNB.Int64(), int64(0))
		require.Equal(t, ionPrice, ionPriceReturned)
		require.Equal(t, bnbPrice, bnbPriceReturned)
		require.Equal(t, "100000", p.ContentTokenParams.FinalPrice)
		require.Equal(t, "10000", p.ContentTokenParams.InitialPrice)
		require.Equal(t, "1000000000000000000000", p.ContentTokenParams.EmissionVolume)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.ContentTokenParams.BondingCurveAlgAddress)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.FeeSponsorAddress)
		require.Equal(t, "post", p.FeeSponsorId)
	})
	sixThousand, _ := big.NewInt(0).SetString("6000000000000000000000", 10)
	backend6000, bondingCurveAddr, bondingCurveCaller := fixture.SetupMockedBondingCurveBackend(t, &fixture.MockBackendConfig{
		BuyPrice:  big.NewInt(950000000000000000), // 0.95 tokens
		SellPrice: sixThousand,                    // 6000 tokens
	})
	defer backend6000.Close()
	bc6000 := fixture.CreateMockedBondingCurveInstance(bondingCurveCaller, bondingCurveAddr)
	ta.bondingCurve = bc6000

	t.Run("sell_xcom_post_token_1plus_swap_for_bnb", func(t *testing.T) {
		xcomPostID := "999888777666"

		amount := big.NewInt(1000000000000000000) // 1 BNB token
		p, err := ta.GetTokenPricing(ctx, xcomPostID, TradeTypeSell, nil, amount, nil, 0)
		tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
		require.NoError(t, err)
		require.Equal(t, "6000000000000000000000", tokensOut.String(), "Should return 6000 ION")
		require.InDelta(t, 600, tokenPriceUSD, 0.0001, "Should be $600 for 1 bnb")
		require.InDelta(t, tokensBNB.Int64(), amount.Int64(), 500)
		require.Equal(t, ionPrice, ionPriceReturned)
		require.Equal(t, bnbPrice, bnbPriceReturned)
	})
	t.Run("sell_xcom_post_token_1plus_swap_for_usd", func(t *testing.T) {
		xcomPostID := "999888777666"

		usdAmount := float64(600.00)
		p, err := ta.GetTokenPricing(ctx, xcomPostID, TradeTypeSell, nil, nil, nil, usdAmount)
		tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
		require.NoError(t, err)
		require.Equal(t, "6000000000000000000000", tokensOut.String(), "Should return 1.05 ION(mocked, not actually calculated)")
		require.InDelta(t, big.NewInt(1000000000000000000).Int64(), tokensBNB.Int64(), 500, "Should return 1 BNB")
		require.InDelta(t, usdAmount, tokenPriceUSD, 0.0001, "Should be $600")
		require.Equal(t, ionPrice, ionPriceReturned)
		require.Equal(t, bnbPrice, bnbPriceReturned)
	})
	ta.bondingCurve = regularCurve
	// ========== ONLINE_PLUS Tests ==========
	t.Run("buy_online_plus_profile_token_first_swap_with_fat_address", func(t *testing.T) {
		// Creator token
		creatorPubkey := "creator_online_plus_1"
		creatorExternalAddr := BuildProfileExternalAddress(creatorPubkey) // "0:creator_online_plus_1:"
		creatorContractAddr := "0x4444444444444444444444444444444444444444"

		fatAddressBytes := buildFatAddressV2Single(
			"Creator Token", "CREA", creatorExternalAddr, 0x61, // 'a' = profile token
			common.Address{}, common.Address{},
		)
		fatAddressHex := "0x" + common.Bytes2Hex(fatAddressBytes)

		amount := big.NewInt(1000000000000000000) // 1 ION
		p, err := ta.GetTokenPricing(ctx, fatAddressHex, TradeTypeBuy, amount, nil, nil, 0)
		require.NoError(t, err)
		tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
		require.Equal(t, big.NewInt(950000000000000000).String(), tokensOut.String())
		require.InDelta(t, 0.1, tokenPriceUSD, 0.0001)
		require.Greater(t, tokensBNB.Int64(), int64(0))
		require.Equal(t, ionPrice, ionPriceReturned)
		require.Equal(t, bnbPrice, bnbPriceReturned)
		require.Equal(t, "100000000", p.CreatorTokenParams.FinalPrice)
		require.Equal(t, "1000000", p.CreatorTokenParams.InitialPrice)
		require.Equal(t, "1000000000000000000000", p.CreatorTokenParams.EmissionVolume)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.CreatorTokenParams.BondingCurveAlgAddress)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.FeeSponsorAddress)
		require.Equal(t, "profile", p.FeeSponsorId)
		// Insert token for 1+ swap test
		helperInsertTestUser(t, ctx, db, creatorExternalAddr, creatorPubkey, "Creator User", "", true, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, creatorContractAddr, creatorExternalAddr, "CREA", "profile", creatorExternalAddr, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		_, err = storage.Exec(ctx, db, `UPDATE tokens SET base_token = $1 WHERE contract_address = $2`, ta.cfg.IONTokenAddress, creatorContractAddr)
		require.NoError(t, err)
		helperInsertBaseTokenPrice(t, ctx, db, creatorContractAddr, "CREA", 0.5)
		ta.creatorTokenPricesION.Store(creatorContractAddr, big.NewInt(1))
	})

	t.Run("buy_online_plus_profile_token_1plus_swap", func(t *testing.T) {
		creatorExternalAddr := BuildProfileExternalAddress("creator_online_plus_1")

		amount := big.NewInt(1000000000000000000)
		p, err := ta.GetTokenPricing(ctx, creatorExternalAddr, TradeTypeBuy, amount, nil, nil, 0)
		tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
		require.NoError(t, err)
		require.Equal(t, big.NewInt(950000000000000000).String(), tokensOut.String())
		require.InDelta(t, 0.1, tokenPriceUSD, 0.0001)
		require.Greater(t, tokensBNB.Int64(), int64(0))
		require.Equal(t, ionPrice, ionPriceReturned)
		require.Equal(t, bnbPrice, bnbPriceReturned)
		require.Equal(t, "100000000", p.CreatorTokenParams.FinalPrice)
		require.Equal(t, "1000000", p.CreatorTokenParams.InitialPrice)
		require.Equal(t, "1000000000000000000000", p.CreatorTokenParams.EmissionVolume)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.CreatorTokenParams.BondingCurveAlgAddress)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.FeeSponsorAddress)
		require.Equal(t, "profile", p.FeeSponsorId)
	})

	t.Run("sell_online_plus_profile_token_1plus_swap", func(t *testing.T) {
		creatorExternalAddr := BuildProfileExternalAddress("creator_online_plus_1")

		amount := big.NewInt(1000000000000000000)
		p, err := ta.GetTokenPricing(ctx, creatorExternalAddr, TradeTypeSell, amount, nil, nil, 0)
		tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
		require.NoError(t, err)
		require.Equal(t, big.NewInt(1050000000000000000).String(), tokensOut.String())
		require.InDelta(t, 0.105, tokenPriceUSD, 0.0001)
		require.Greater(t, tokensBNB.Int64(), int64(0))
		require.Equal(t, ionPrice, ionPriceReturned)
		require.Equal(t, bnbPrice, bnbPriceReturned)
	})

	// Content token with double swap (ION -> Creator -> Content)
	// User pays 1 creator token, gets content tokens back
	creatorPubkey := "creator_double_swap"
	creatorExternalAddr := BuildProfileExternalAddress(creatorPubkey)
	creatorContractAddr := "0x5555555555555555555555555555555555555555"
	contentExternalAddr := "30175:" + creatorPubkey + ":post123"

	t.Run("buy_online_plus_content_token_double_swap_with_fat_address", func(t *testing.T) {
		_, err := storage.Exec(ctx, db, `UPDATE tokens SET base_token = $1 WHERE contract_address = $2`, ta.cfg.IONTokenAddress, creatorContractAddr)
		require.NoError(t, err)
		ta.creatorTokenPricesION.Store(creatorContractAddr, big.NewInt(1))

		fatAddressBytes := buildFatAddressV2Double(
			"Creator Token", "CREADBL", creatorExternalAddr, 0x61,
			"Content Token", "CONT", contentExternalAddr, 0x62,
			common.Address{}, common.Address{},
		)
		fatAddressHex := "0x" + common.Bytes2Hex(fatAddressBytes)

		amount := big.NewInt(1000000000000000000) // 1 creator token
		p, err := ta.GetTokenPricing(ctx, fatAddressHex, TradeTypeBuy, amount, nil, nil, 0)
		tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
		require.NoError(t, err)
		// For content token, base is creator token, so we get 0.95 content tokens for 1 creator token
		require.Equal(t, big.NewInt(950000000000000000).String(), tokensOut.String(), "Should get 0.95 content tokens")
		require.InDelta(t, 0.1, tokenPriceUSD, 0.0001, "Should be $0.1 (1 spent * $0.1 (ION spent, twisted))")
		require.Greater(t, tokensBNB.Int64(), int64(0))
		require.Equal(t, ionPrice, ionPriceReturned)
		require.Equal(t, bnbPrice, bnbPriceReturned)
		require.Equal(t, "999999999999999", p.ContentTokenParams.FinalPrice)   // 1e18, 1 to 1 to ION
		require.Equal(t, "100000000000000", p.ContentTokenParams.InitialPrice) // 1e18, 1 to 1 to ION
		require.Equal(t, "1000000000000000000000", p.ContentTokenParams.EmissionVolume)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.ContentTokenParams.BondingCurveAlgAddress)
		require.NotNil(t, p.CreatorTokenParams)
		require.Equal(t, "100000000", p.CreatorTokenParams.FinalPrice)
		require.Equal(t, "1000000", p.CreatorTokenParams.InitialPrice)
		require.Equal(t, "1000000000000000000000", p.CreatorTokenParams.EmissionVolume)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.CreatorTokenParams.BondingCurveAlgAddress)

		require.Equal(t, "0x000000000000000000000000000000000000dead", p.FeeSponsorAddress)
		require.Equal(t, "post", p.FeeSponsorId)
		// Insert content token for 1+ swap test
		contentContractAddr := "0x6666666666666666666666666666666666666666"
		helperInsertTestToken(t, ctx, db, contentContractAddr, contentExternalAddr, "CONT", "post", creatorExternalAddr, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		_, err = storage.Exec(ctx, db, `UPDATE tokens SET base_token = $1 WHERE contract_address = $2`, creatorContractAddr, contentContractAddr)
		require.NoError(t, err)
	})

	t.Run("buy_online_plus_content_token_1plus_swap", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, creatorExternalAddr, creatorPubkey, "Creator Double", "", true, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, creatorContractAddr, creatorExternalAddr, "CREADBL", "profile", creatorExternalAddr, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperInsertBaseTokenPrice(t, ctx, db, creatorContractAddr, "CREADBL", 0.75)

		creatorPubkey := "creator_double_swap"
		contentExternalAddr := "30175:" + creatorPubkey + ":post123"

		amount := big.NewInt(1000000000000000000) // 1 creator token
		p, err := ta.GetTokenPricing(ctx, contentExternalAddr, TradeTypeBuy, amount, nil, nil, 0)
		require.NoError(t, err)
		tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
		require.Equal(t, big.NewInt(950000000000000000).String(), tokensOut.String(), "Should get 0.95 content tokens")
		require.InDelta(t, 0.75, tokenPriceUSD, 0.0001, "Should be $0.75")
		require.Greater(t, tokensBNB.Int64(), int64(0))
		require.Equal(t, ionPrice, ionPriceReturned)
		require.Equal(t, bnbPrice, bnbPriceReturned)
		require.Equal(t, "100000", p.ContentTokenParams.FinalPrice)
		require.Equal(t, "10000", p.ContentTokenParams.InitialPrice)
		require.Equal(t, "1000000000000000000000", p.ContentTokenParams.EmissionVolume)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.ContentTokenParams.BondingCurveAlgAddress)
		require.Equal(t, "0x000000000000000000000000000000000000dead", p.FeeSponsorAddress)
		require.Equal(t, "post", p.FeeSponsorId)
	})

	t.Run("sell_online_plus_content_token_1plus_swap", func(t *testing.T) {
		creatorPubkey := "creator_double_swap"
		contentExternalAddr := "30175:" + creatorPubkey + ":post123"

		amount := big.NewInt(1000000000000000000) // 1 content token
		p, err := ta.GetTokenPricing(ctx, contentExternalAddr, TradeTypeSell, amount, nil, nil, 0)
		tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
		require.NoError(t, err)
		require.Equal(t, big.NewInt(1050000000000000000).String(), tokensOut.String(), "Should get 1.05 creator tokens")
		require.InDelta(t, 0.7875, tokenPriceUSD, 0.0001, "Should be 0.7875 (1.05 base * $0.75)")
		require.Greater(t, tokensBNB.Int64(), int64(0))
		require.Equal(t, ionPrice, ionPriceReturned)
		require.Equal(t, bnbPrice, bnbPriceReturned)
	})

	// ========== Error Cases ==========
	t.Run("error_invalid_fat_address_v2_format", func(t *testing.T) {
		invalidFatAddr := "0x0201000107"
		amount := big.NewInt(1000000000000000000)
		_, err := ta.GetTokenPricing(ctx, invalidFatAddr, TradeTypeBuy, amount, nil, nil, 0)
		require.Error(t, err)
	})

	t.Run("fallback_to_ion_price_for_invalid_hex_address", func(t *testing.T) {
		invalidAddresses := []string{"-", "xyz", "0xggg", "abc"} // Invalid hex characters

		for _, addr := range invalidAddresses {
			amount := big.NewInt(1000000000000000000)
			p, err := ta.GetTokenPricing(ctx, addr, TradeTypeBuy, amount, nil, nil, 0)
			tokensOut, tokensBNB, tokenPriceUSD, ionPriceReturned, bnbPriceReturned := p.AmountInBase, p.AmountInBNB, p.AmountInUSD, p.IonPriceInUSD, p.BNBPriceInUSD
			require.NoError(t, err, "Should not return error for invalid hex: %s", addr)
			require.Nil(t, tokensOut, "tokensOut should be nil for invalid hex: %s", addr)
			require.Nil(t, tokensBNB, "tokensBNB should be nil for invalid hex: %s", addr)
			require.Equal(t, 0.0, tokenPriceUSD, "tokenPriceUSD should be 0 for invalid hex: %s", addr)
			require.Equal(t, ionPrice, ionPriceReturned, "Should return ION price for invalid hex: %s", addr)
			require.Equal(t, bnbPrice, bnbPriceReturned, "Should return BNB price for invalid hex: %s", addr)
		}
	})
}
