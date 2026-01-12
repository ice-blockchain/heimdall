// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/ddl"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/connectors/storage/v2/fixture"
)

var (
	testPgContainer *fixture.Container
)

func TestMain(m *testing.M) {
	ctx, cancel := context.WithCancel(context.Background())
	testPgContainer = fixture.New(ctx)
	code := m.Run()
	testPgContainer.Close(ctx)
	cancel()

	if code != 0 {
		os.Exit(code)
	}
}

func helperCreateDB(t *testing.T) (*storage.DB, func()) {
	t.Helper()

	connString, release := testPgContainer.MustTempDB(t.Context())
	db := storage.MustConnectWithCfg(t.Context(),
		&storage.Cfg{
			PrimaryURL:   connString,
			ReplicaURLs:  []string{connString},
			RunDDL:       true,
			IgnoreGlobal: true,
		},
		storage.NewFilesystemDDL(&ddl.Files, schemeMigrationTableName),
	)
	require.NotNil(t, db)

	return db, func() {
		db.Close()
		release()
	}
}

func TestStorageDDL(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	require.NoError(t, db.Ping(t.Context()))
}

const (
	testHandleOpsInput          = "0x74fa412100000000000000000000000000000000000000000000000000000000000000601b071d768b34be2e06c87954537b12eeadab4991131acd5a35e41feff3ae8ddc8a53cdc35a5ffd52c313a3dde16005c2ea88b46dd9d3228363a5ca438a0c037600000000000000000000000000000000000000000000000000000000000001588b5a70a21af8bd7bdb38c0fac5cf3a81079d25950000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010483362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000003e733628714200000000000000000000000000000000000000000000000000003dd356e57a5d8000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e7ebd115c95248b512c9b0c9fa4bb06b49ffbfb60000000000000000000000000000000000000000"
	testDirectSwapInput         = "0x83362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000003e733628714200000000000000000000000000000000000000000000000000003dd356e57a5d8000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e7ebd115c95248b512c9b0c9fa4bb06b49ffbfb60000000000000000000000000000000000000000"
	testHandleOpsWithFatAddress = "0x74fa41210000000000000000000000000000000000000000000000000000000000000060421f3d9704e56bdf92fb6dd1f044509482e524dba85a372cdc0278deca73ba5f24c40b74fa837fb2a2693b0b5472a62637e72197c43e659638b22381e1faf58100000000000000000000000000000000000000000000000000000000000002988b5a70a21af8bd7bdb38c0fac5cf3a81079d25950000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024483362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000001a055690d9db800000000000000000000000000000000000000000000000000019c2b98a4851a000000000000000000000000000000000000000000000000000000000000000000141a4a90f4d582d54a8e0d1d6f3c3d2d43c5378f5000000000000000000000000000000000000000000000000000000000000000000000000000000000000001566b406b6279d7e491506651b776483187ceb5eb75424ae51b00000000000000000000000000000000000000001a4a90f4d582d54a8e0d1d6f3c3d2d43c5378f5033303137353a663864313635353966623134633266656439306262353530353763623836363930353265626666353938373363386661363162393363626262303739396630333a30313962396434642d643637392d376331332d613162662d3065613663343433613865346638643136353539666231346332666564393062623535303537636238363639303532656266663539383733633866613631623933636262623037393966303333303137353a663864313635353966623134633266656439306262353530353763623836363930353265626666353938373363386661363162393363626262303739396630333a30313962396434642d643637392d376331332d613162662d306561366334343361386534000000000000000000000000000000000000"
	testExpectedBaseToken       = "0x2c73996babf1a06c2c057177353293f7ca0907c8"
)

func TestExtractSwapCalldataFromCustomHandleOps(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()
	t.Run("extracts_4param_swap_from_handleOps", func(t *testing.T) {
		type result struct {
			Extracted string `db:"extract_swap_calldata_from_custom_handleops"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT extract_swap_calldata_from_custom_handleops($1)`, testHandleOpsInput)
		require.NoError(t, err)
		require.NotEqual(t, testHandleOpsInput, r.Extracted, "Should extract inner calldata")
		require.Contains(t, r.Extracted, "0x83362e17", "Extracted calldata should start with 4-param swap selector")
		require.True(t, len(r.Extracted) < len(testHandleOpsInput), "Extracted calldata should be shorter")

		expectedSwapStart := "0x83362e17"
		require.True(t, strings.HasPrefix(r.Extracted, expectedSwapStart), "Extracted swap should start with selector 0x83362e17")
	})

	t.Run("extracts_5param_swap_from_handleOps", func(t *testing.T) {
		handleOpsWith5Param := strings.Replace(testHandleOpsInput, "83362e17", "027c101d", 1)
		type result struct {
			Extracted string `db:"extract_swap_calldata_from_custom_handleops"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT extract_swap_calldata_from_custom_handleops($1)`, handleOpsWith5Param)
		require.NoError(t, err)
		require.Contains(t, r.Extracted, "0x027c101d", "Should extract 5-param swap selector")
	})
	t.Run("returns_direct_swap_unchanged", func(t *testing.T) {
		type result struct {
			Extracted string `db:"extract_swap_calldata_from_custom_handleops"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT extract_swap_calldata_from_custom_handleops($1)`, testDirectSwapInput)
		require.NoError(t, err)
		require.Equal(t, testDirectSwapInput, r.Extracted, "Direct swap should be returned unchanged")
	})

	t.Run("handles_null_input", func(t *testing.T) {
		type result struct {
			Extracted *string `db:"result"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT extract_swap_calldata_from_custom_handleops(NULL) as result`)
		require.NoError(t, err)
		require.Nil(t, r.Extracted, "NULL input should return NULL")
	})

	t.Run("handles_short_input", func(t *testing.T) {
		type result struct {
			Extracted string `db:"extract_swap_calldata_from_custom_handleops"`
		}
		shortInput := "0x1234"
		r, err := storage.Get[result](ctx, db, `SELECT extract_swap_calldata_from_custom_handleops($1)`, shortInput)
		require.NoError(t, err)
		require.Equal(t, shortInput, r.Extracted, "Short input should be returned unchanged")
	})

	t.Run("handles_non_custom_handleops_selector", func(t *testing.T) {
		otherInput := "0x12345678" + strings.Repeat("00", 100)

		type result struct {
			Extracted string `db:"extract_swap_calldata_from_custom_handleops"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT extract_swap_calldata_from_custom_handleops($1)`, otherInput)
		require.NoError(t, err)
		require.Equal(t, otherInput, r.Extracted, "Non-handleOps should return unchanged")
	})

	t.Run("handles_custom_handleops_without_swap", func(t *testing.T) {
		handleOpsNoSwap := "0x74fa4121" + strings.Repeat("aa", 200)

		type result struct {
			Extracted string `db:"extract_swap_calldata_from_custom_handleops"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT extract_swap_calldata_from_custom_handleops($1)`, handleOpsNoSwap)
		require.NoError(t, err)
		require.Equal(t, handleOpsNoSwap, r.Extracted, "handleOps without swap should return unchanged")
	})
}

func TestDecodeBaseTokenFromInput(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()

	t.Run("decodes_from_handleops_transaction", func(t *testing.T) {
		type result struct {
			BaseToken *string `db:"base_token"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT decode_base_token_from_input($1) as base_token`, testHandleOpsInput)
		require.NoError(t, err)
		require.NotNil(t, r.BaseToken)
		require.Equal(t, testExpectedBaseToken, *r.BaseToken, "Should correctly decode base token from handleOps")
	})

	t.Run("decodes_from_direct_swap", func(t *testing.T) {
		type result struct {
			BaseToken *string `db:"base_token"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT decode_base_token_from_input($1) as base_token`, testDirectSwapInput)
		require.NoError(t, err)
		require.NotNil(t, r.BaseToken)
		require.Equal(t, testExpectedBaseToken, *r.BaseToken, "Should correctly decode base token from direct swap")
	})
}

func TestDecodeToTokenFromInput(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()

	t.Run("returns_empty_string_for_thin_address_handleops", func(t *testing.T) {
		type result struct {
			ToToken string `db:"decode_to_token_from_input"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT decode_to_token_from_input($1)`, testHandleOpsInput)
		require.NoError(t, err)
		require.Empty(t, r.ToToken, "Thin address (subsequent swap) should return empty string")
		type baseTokenResult struct {
			BaseToken *string `db:"base_token"`
		}
		br, err := storage.Get[baseTokenResult](ctx, db, `SELECT decode_base_token_from_input($1) as base_token`, testHandleOpsInput)
		require.NoError(t, err)
		require.NotNil(t, br.BaseToken, "Base token should be decoded even with thin toToken")
	})

	t.Run("returns_empty_string_for_thin_address_handleops_after_token_creation", func(t *testing.T) {
		type result struct {
			ToToken string `db:"decode_to_token_from_input"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT decode_to_token_from_input($1)`, testHandleOpsWithFatAddress)
		require.NoError(t, err)
		require.Empty(t, r.ToToken, "Thin address should return empty string, even in handleOps transaction")
	})

	t.Run("returns_empty_string_for_thin_address_direct_swap", func(t *testing.T) {
		type result struct {
			ToToken string `db:"decode_to_token_from_input"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT decode_to_token_from_input($1)`, testDirectSwapInput)
		require.NoError(t, err)
		require.Empty(t, r.ToToken, "Thin address in direct swap should return empty string")
	})

	t.Run("handles_null_input_gracefully", func(t *testing.T) {
		type result struct {
			ToToken string `db:"decode_to_token_from_input"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT decode_to_token_from_input(NULL)`)
		require.NoError(t, err)
		require.Empty(t, r.ToToken, "NULL input should return empty string")
	})

	t.Run("handles_malformed_input_gracefully", func(t *testing.T) {
		type result struct {
			ToToken string `db:"decode_to_token_from_input"`
		}
		malformed := "0xinvalidhex"
		r, err := storage.Get[result](ctx, db, `SELECT decode_to_token_from_input($1)`, malformed)
		require.NoError(t, err)
		require.Empty(t, r.ToToken, "Malformed input should be handled gracefully")
	})

	t.Run("correctly_identifies_thin_vs_fat_address", func(t *testing.T) {
		type result struct {
			ToToken string `db:"decode_to_token_from_input"`
		}
		// Thin.
		r1, err := storage.Get[result](ctx, db, `SELECT decode_to_token_from_input($1)`, testHandleOpsInput)
		require.NoError(t, err)
		require.Empty(t, r1.ToToken, "Should detect thin address and return empty string")

		// Direct swap (also thin)
		r2, err := storage.Get[result](ctx, db, `SELECT decode_to_token_from_input($1)`, testDirectSwapInput)
		require.NoError(t, err)
		require.Empty(t, r2.ToToken, "Direct swap should also be thin address and return empty string")
	})

	// V2 Fat Address
	t.Run("v2_single_token_fat_address", func(t *testing.T) {
		fatAddress := "02" + // version
			"01" + // recordsCount
			"0003" + // presenceMask
			"0a040d61" + // header
			"00000000" + // tokenMask
			"0000000000000000000000000000000000000000" + // bonding addr
			"5465737420546f6b656e" + // "Test Token"
			"54455354" + // "TEST"
			"303a7075626b65793a74657374" + // "0:pubkey:test"
			"1111111111111111111111111111111111111111" + // creator
			"2222222222222222222222222222222222222222" // affiliate

		txInput := "0x027c101d" + // swap() signature
			"0000000000000000000000000000000000000000000000000000000000000080" + // fromToken offset
			"00000000000000000000000000000000000000000000000000000000000000c0" + // toToken offset
			"0000000000000000000000000000000000000000000000000de0b6b3a7640000" + // amountIn
			"0000000000000000000000000000000000000000000000000dbd2fc137a30000" + // minReturn
			"0000000000000000000000000000000000000000000000000000000000000014" + // fromToken length
			"2c73996babf1a06c2c057177353293f7ca0907c8000000000000000000000000" + // fromToken
			"0000000000000000000000000000000000000000000000000000000000000063" + // toToken length (99 bytes)
			fatAddress +
			"000000000000000000000000000000000000000000000000000000000000" // padding

		result, err := storage.Get[string](ctx, db,
			`SELECT decode_to_token_from_input($1)`, txInput)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "0:pubkey:test", *result, "Should extract external address from V2 fat address")
	})

	t.Run("thin_address_returns_empty", func(t *testing.T) {
		txInput := "0x027c101d" +
			"0000000000000000000000000000000000000000000000000000000000000080" +
			"00000000000000000000000000000000000000000000000000000000000000c0" +
			"0000000000000000000000000000000000000000000000000de0b6b3a7640000" +
			"0000000000000000000000000000000000000000000000000dbd2fc137a30000" +
			"0000000000000000000000000000000000000000000000000000000000000014" +
			"2c73996babf1a06c2c057177353293f7ca0907c8000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000014" + // toToken length (20)
			"0f93afe4f21f8885b99932214c66be3ff42e2162000000000000000000000000" // thin address

		result, err := storage.Get[string](ctx, db,
			`SELECT decode_to_token_from_input($1)`, txInput)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "", *result, "Thin address should return empty string")
	})
}

func TestParseCustomHandleOps(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()

	t.Run("returns_false_for_direct_swap", func(t *testing.T) {
		type result struct {
			IsCustomHandleOps bool `db:"is_custom_handleops"`
		}
		r, err := storage.Get[result](ctx, db, `
				SELECT (parse_custom_handleops($1)->>'isCustomHandleOps')::BOOLEAN as is_custom_handleops
			`, testDirectSwapInput)
		require.NoError(t, err)
		require.False(t, r.IsCustomHandleOps, "Direct swap should not be identified as handleOps")
	})

	t.Run("handles_null_input", func(t *testing.T) {
		type result struct {
			IsCustomHandleOps bool `db:"is_custom_handleops"`
		}
		r, err := storage.Get[result](ctx, db, `
				SELECT COALESCE((parse_custom_handleops(NULL)->>'isCustomHandleOps')::BOOLEAN, false) as is_custom_handleops
			`)
		require.NoError(t, err)
		require.False(t, r.IsCustomHandleOps)
	})

	t.Run("handles_short_input", func(t *testing.T) {
		type result struct {
			IsCustomHandleOps bool `db:"is_custom_handleops"`
		}
		shortInput := "0x1234"
		r, err := storage.Get[result](ctx, db, `
				SELECT (parse_custom_handleops($1)->>'isCustomHandleOps')::BOOLEAN as is_custom_handleops
			`, shortInput)
		require.NoError(t, err)
		require.False(t, r.IsCustomHandleOps, "Short input should not be handleOps")
	})

	t.Run("handles_non_handleOps_selector", func(t *testing.T) {
		type result struct {
			IsCustomHandleOps bool `db:"is_custom_handleops"`
		}
		otherInput := "0x12345678" + strings.Repeat("00", 100)
		r, err := storage.Get[result](ctx, db, `
				SELECT (parse_custom_handleops($1)->>'isCustomHandleOps')::BOOLEAN as is_custom_handleops
			`, otherInput)
		require.NoError(t, err)
		require.False(t, r.IsCustomHandleOps, "Non-handleOps selector should return false")
	})

	t.Run("verifies_swap_extraction_from_production_transactions", func(t *testing.T) {
		productionTxs := []struct {
			name    string
			txInput string
			txHash  string
		}{
			{
				name:    "tx_0x20cb3aa6",
				txHash:  "0x20cb3aa6a68c937444686fc799659d4d32c7eb0a9834f7e7eed497083795a4e3",
				txInput: testHandleOpsInput,
			},
			{
				name:    "tx_0x6c56b49b",
				txHash:  "0x6c56b49b88721082579b118016d0d2c8245b1b0491d0bf038c1ff312537c505e",
				txInput: "0x74fa412100000000000000000000000000000000000000000000000000000000000000602b5cb9ef5ee1c2d249d0f78bf82142fe7a00f85e9a37ceb003d542d0f6bdabbfeada3351632e8831f09fd360a4b5687daf8c08631473c22186721d5e9764825c00000000000000000000000000000000000000000000000000000000000001588b5a70a21af8bd7bdb38c0fac5cf3a81079d25950000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010483362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000003e733628714200000000000000000000000000000000000000000000000000003dd356e57a5d8000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000014704def84ed8e2fa1d362b2936d3bb364a53f5fc90000000000000000000000000000000000000000",
			},
			{
				name:    "tx_0xd62f3d03",
				txHash:  "0xd62f3d03d809ab8e0e9c57d335ab918d90d669004e4c584b2d137a4611c79d44",
				txInput: "0x74fa41210000000000000000000000000000000000000000000000000000000000000060aa1d2565c2dc29cfbc04efa1c8c47f24f180abe1a10ceeafc8dbe49f70d653c33b65a6414bcdc65a1a0f7815add3b77cfd600ff9166d9e5959a59e1f91d454d200000000000000000000000000000000000000000000000000000000000001588b5a70a21af8bd7bdb38c0fac5cf3a81079d25950000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010483362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000056bc75e2d631000000000000000000000000000000000000000000000000000055de6a779bbac000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e7ebd115c95248b512c9b0c9fa4bb06b49ffbfb60000000000000000000000000000000000000000",
			},
		}

		for _, tc := range productionTxs {
			t.Run(tc.name, func(t *testing.T) {
				type extractResult struct {
					Extracted string `db:"extracted"`
				}
				er, err := storage.Get[extractResult](ctx, db, `
						SELECT extract_swap_calldata_from_custom_handleops($1) as extracted
					`, tc.txInput)
				require.NoError(t, err)

				require.Contains(t, er.Extracted, "0x83362e17", "Should extract swap selector")
				require.True(t, len(er.Extracted) < len(tc.txInput), "Extracted should be shorter than original")

				type baseTokenResult struct {
					BaseToken *string `db:"base_token"`
				}
				br, err := storage.Get[baseTokenResult](ctx, db, `
						SELECT decode_base_token_from_input($1) as base_token
					`, tc.txInput)
				require.NoError(t, err)
				require.NotNil(t, br.BaseToken)
				require.Equal(t, testExpectedBaseToken, *br.BaseToken, "Base token must be ION")
			})
		}
	})
}

func TestDecodeUint256(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()

	t.Run("decode_input_amount_from_swapped_event", func(t *testing.T) {
		result, err := storage.Get[string](ctx, db,
			`SELECT decode_uint256('0x000000000000000000000000000000000000000000000035203b67bccad00000', 0)::TEXT`)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "980000000000000000000", *result, "Expected inputAmount 980 tokens")
	})

	t.Run("decode_fee_from_swapped_event", func(t *testing.T) {
		result, err := storage.Get[string](ctx, db,
			`SELECT decode_uint256('0x000000000000000000000000000000000000000000000001100130279da80000', 0)::TEXT`)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "19600000000000000000", *result, "Expected fee 19.6 tokens")
	})

	t.Run("decode_output_amount", func(t *testing.T) {
		result, err := storage.Get[string](ctx, db,
			`SELECT decode_uint256('0x000000000000000000000000000000000000000000000034103a37952d280000', 0)::TEXT`)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "960400000000000000000", *result, "Expected outputAmount 960.4 tokens")
	})
}

func TestDecodeStringABI(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()

	t.Run("decode_abi_encoded_string", func(t *testing.T) {
		testData := "0x" +
			"0000000000000000000000000000000000000000000000000000000000000020" + // offset = 32 bytes
			"000000000000000000000000000000000000000000000000000000000000000a" + // length = 10 bytes
			"5465737420546f6b656e00000000000000000000000000000000000000000000" // "Test Token" padded

		result, err := storage.Get[string](ctx, db,
			`SELECT decode_string_abi($1, 0)`, testData)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "Test Token", *result)
	})
}

func TestRealProductionEventData(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()
	ctx := t.Context()

	t.Run("swapped_event_first_token", func(t *testing.T) {
		swappedData := "0x" +
			"0000000000000000000000000000000000000000000000000000000000000000" + // direction = false (BUY)
			"000000000000000000000000aaa1de4bef569c093e31f31e2a9765bfb7823c58" + // feeToken
			"000000000000000000000000000000000000000000000035203b67bccad00000" + // inputAmount
			"000000000000000000000000000000000000000000000034103a37952d280000" + // outputAmount
			"000000000000000000000000000000000000000000000001100130279da80000" // fee

		direction, err := storage.Get[bool](ctx, db,
			`SELECT decode_uint256($1, 0) = 1`, swappedData)
		require.NoError(t, err)
		require.NotNil(t, direction)
		require.False(t, *direction, "Direction should be BUY (false)")

		inputAmount, err := storage.Get[string](ctx, db,
			`SELECT decode_uint256($1, 2)::TEXT`, swappedData)
		require.NoError(t, err)
		require.NotNil(t, inputAmount)
		require.Equal(t, "980000000000000000000", *inputAmount, "Input amount: 980 tokens")

		outputAmount, err := storage.Get[string](ctx, db,
			`SELECT decode_uint256($1, 3)::TEXT`, swappedData)
		require.NoError(t, err)
		require.NotNil(t, outputAmount)
		require.Equal(t, "960400000000000000000", *outputAmount, "Output amount: 960.4 tokens")

		fee, err := storage.Get[string](ctx, db,
			`SELECT decode_uint256($1, 4)::TEXT`, swappedData)
		require.NoError(t, err)
		require.NotNil(t, fee)
		require.Equal(t, "19600000000000000000", *fee, "Fee: 19.6 tokens")
	})

	t.Run("swapped_event_second_token", func(t *testing.T) {
		swappedData := "0x" +
			"0000000000000000000000000000000000000000000000000000000000000000" + // direction = false
			"000000000000000000000000aaa1de4bef569c093e31f31e2a9765bfb7823c58" + // feeToken
			"00000000000000000000000000000000000000000000003635c9adc5dea00000" + // inputAmount
			"000000000000000000000000000000000000000000000035203b67bccad00000" + // outputAmount
			"000000000000000000000000000000000000000000000001158e460913d00000" // fee

		inputAmount, err := storage.Get[string](ctx, db,
			`SELECT decode_uint256($1, 2)::TEXT`, swappedData)
		require.NoError(t, err)
		require.NotNil(t, inputAmount)
		require.Equal(t, "1000000000000000000000", *inputAmount, "Input: 1000 tokens")

		outputAmount, err := storage.Get[string](ctx, db,
			`SELECT decode_uint256($1, 3)::TEXT`, swappedData)
		require.NoError(t, err)
		require.NotNil(t, outputAmount)
		require.Equal(t, "980000000000000000000", *outputAmount, "Output: 980 tokens")

		fee, err := storage.Get[string](ctx, db,
			`SELECT decode_uint256($1, 4)::TEXT`, swappedData)
		require.NoError(t, err)
		require.NotNil(t, fee)
		require.Equal(t, "20000000000000000000", *fee, "Fee: 20 tokens")
	})

	t.Run("fee_accrued_event", func(t *testing.T) {
		feeAccruedData := "0x" +
			"000000000000000000000000000000000000000000000001100130279da80000" + // total fee
			"00000000000000000000000000000000000000000000000088009813ced40000" + // toCreator
			"0000000000000000000000000000000000000000000000000000000000000000" + // toAffiliate
			"00000000000000000000000000000000000000000000000088009813ced40000" // toBurn

		type FeeData struct {
			TotalFee    string `db:"total_fee"`
			ToCreator   string `db:"to_creator"`
			ToAffiliate string `db:"to_affiliate"`
			ToBurn      string `db:"to_burn"`
		}

		result, err := storage.Get[FeeData](ctx, db,
			`SELECT 
				decode_uint256($1, 0)::TEXT as total_fee,
				decode_uint256($1, 1)::TEXT as to_creator,
				decode_uint256($1, 2)::TEXT as to_affiliate,
				decode_uint256($1, 3)::TEXT as to_burn`,
			feeAccruedData)
		require.NoError(t, err)
		require.NotNil(t, result)

		require.Equal(t, "19600000000000000000", result.TotalFee, "Total fee: 19.6 tokens")
		require.Equal(t, "9800000000000000000", result.ToCreator, "To creator: 9.8 tokens (50%)")
		require.Equal(t, "0", result.ToAffiliate, "To affiliate: 0 tokens")
		require.Equal(t, "9800000000000000000", result.ToBurn, "To burn: 9.8 tokens (50%)")

		sum, err := storage.Get[string](ctx, db,
			`SELECT ($1::NUMERIC + $2::NUMERIC + $3::NUMERIC)::TEXT`,
			result.ToCreator, result.ToAffiliate, result.ToBurn)
		require.NoError(t, err)
		require.NotNil(t, sum)
		require.Equal(t, result.TotalFee, *sum, "Fee distribution should add up correctly")
	})

	t.Run("slippage_checked_event", func(t *testing.T) {
		slippageData := "0x" +
			"0000000000000000000000000000000000000000000000000000000000000000" + // minReturn = 0
			"000000000000000000000000000000000000000000000034103a37952d280000" // actualOut

		type SlippageData struct {
			MinReturn string `db:"min_return"`
			ActualOut string `db:"actual_out"`
		}

		result, err := storage.Get[SlippageData](ctx, db,
			`SELECT 
				decode_uint256($1, 0)::TEXT as min_return,
				decode_uint256($1, 1)::TEXT as actual_out`,
			slippageData)
		require.NoError(t, err)
		require.NotNil(t, result)

		require.Equal(t, "0", result.MinReturn, "Min return: 0")
		require.Equal(t, "960400000000000000000", result.ActualOut, "Actual out: 960.4 tokens")

		slippageOK, err := storage.Get[bool](ctx, db,
			`SELECT $1::NUMERIC >= $2::NUMERIC`,
			result.ActualOut, result.MinReturn)
		require.NoError(t, err)
		require.NotNil(t, slippageOK)
		require.True(t, *slippageOK, "Slippage check should pass")
	})
}

func TestProcessBondedTokenCreated(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()

	t.Run("function_signature_exists", func(t *testing.T) {
		exists, err := storage.Get[bool](ctx, db, `
			SELECT EXISTS (
				SELECT 1 
				FROM pg_proc p
				JOIN pg_namespace n ON p.pronamespace = n.oid
				WHERE n.nspname = 'public'
				AND p.proname = 'process_bonded_token_created'
				AND pg_get_function_arguments(p.oid) = 'p_topics text[], p_data text, p_block_timestamp timestamp without time zone, p_log_index bigint'
			)
		`)
		require.NoError(t, err)
		require.NotNil(t, exists)
		require.True(t, *exists, "process_bonded_token_created function should exist with correct signature")
	})
}

func TestDoubleSwapTokenCreation(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()
	ctx := t.Context()

	t.Run("decode_v2_double_fat_address", func(t *testing.T) {
		// Build V2 fat address with 2 tokens (profile + content)
		// Global Header: [version=2][recordsCount=2][presenceMask=0x0003]
		// Token 1: Creator Profile (0:pubkey:)
		// Token 2: Content Post (30175:pubkey:dtag)

		creatorName := "Creator Profile"
		creatorSymbol := "PROF"
		creatorExtAddr := "0:89aa679f7727b79492d00c428c1a70ac9f8c28e3ae306842f059a273e484dc9b:"

		contentName := "My First Post"
		contentSymbol := "POST"
		contentExtAddr := "30175:89aa679f7727b79492d00c428c1a70ac9f8c28e3ae306842f059a273e484dc9b:019ba2dc-ab26-78eb-b321-823305185743"

		fatAddr := []byte{
			0x02,       // version = 2
			0x02,       // recordsCount = 2
			0x00, 0x03, // presenceMask (creator | affiliate)
		}

		// Token 1 header (creator profile)
		fatAddr = append(fatAddr,
			byte(len(creatorName)), byte(len(creatorSymbol)), byte(len(creatorExtAddr)), 0x61, // [nameLen][symbolLen][extAddrLen][extType=profile]
			0x00, 0x00, 0x00, 0x00,
		)
		fatAddr = append(fatAddr, make([]byte, 20)...)
		fatAddr = append(fatAddr, []byte(creatorName)...)
		fatAddr = append(fatAddr, []byte(creatorSymbol)...)
		fatAddr = append(fatAddr, []byte(creatorExtAddr)...)

		// Token 2 header (content post)
		fatAddr = append(fatAddr,
			byte(len(contentName)), byte(len(contentSymbol)), byte(len(contentExtAddr)), 0x62, // [nameLen][symbolLen][extAddrLen][extType=post]
			0x00, 0x00, 0x00, 0x00,
		)
		fatAddr = append(fatAddr, make([]byte, 20)...)
		fatAddr = append(fatAddr, []byte(contentName)...)
		fatAddr = append(fatAddr, []byte(contentSymbol)...)
		fatAddr = append(fatAddr, []byte(contentExtAddr)...)

		// Global footer (creator + affiliate addresses)
		creatorAddr := make([]byte, 20)
		creatorAddr[0] = 0x11
		affiliateAddr := make([]byte, 20)
		affiliateAddr[0] = 0x22
		fatAddr = append(fatAddr, creatorAddr...)
		fatAddr = append(fatAddr, affiliateAddr...)

		baseToken := make([]byte, 20)
		baseToken[0] = 0x2c

		// Function selector: 0x83362e17
		txInput := "0x83362e17"

		// fromToken offset (word 0): 0xa0 (160 bytes - after 5 words of params)
		txInput += "00000000000000000000000000000000000000000000000000000000000000a0"
		// toToken offset (word 1): 0xe0 (224 bytes)
		txInput += "00000000000000000000000000000000000000000000000000000000000000e0"
		// amountIn (word 2): 1000 tokens
		txInput += "00000000000000000000000000000000000000000000003635c9adc5dea00000"
		// minReturn (word 3): 990 tokens
		txInput += "0000000000000000000000000000000000000000000000035203b67bccad0000"
		// permit offset (word 4): will be after toToken data
		permitOffset := 224 + 32 + len(fatAddr) // e0 + length word + fat address
		txInput += fmt.Sprintf("%064x", permitOffset)

		// fromToken data (baseToken - 20 bytes)
		txInput += fmt.Sprintf("%064x", 20)                           // length
		txInput += fmt.Sprintf("%-64s", fmt.Sprintf("%x", baseToken)) // padded to 32 bytes

		// toToken data (fat address)
		txInput += fmt.Sprintf("%064x", len(fatAddr)) // length
		txInput += fmt.Sprintf("%x", fatAddr)
		// Pad to 32-byte boundary
		if len(fatAddr)%32 != 0 {
			padding := 32 - (len(fatAddr) % 32)
			txInput += strings.Repeat("0", padding*2)
		}
		// permit data (5 fields: value, deadline, v, r, s)
		txInput += strings.Repeat("0", 64*5)

		type result struct {
			ExternalAddr string `db:"decode_to_token_from_input"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT decode_to_token_from_input($1)`, txInput)
		require.NoError(t, err)
		require.NotNil(t, r)
		expectedExtAddr := creatorExtAddr
		require.Equal(t, expectedExtAddr, r.ExternalAddr, "Should extract first token (profile) external address from V2 double fat address")
	})
}

func TestHandleOpsWithV2FatAddress(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()

	// Transaction structure:
	// Layer 1: handleOps(bytes userOps, uint256 r, uint256 vs)
	// Layer 2: UserOperation with Safe wallet
	// Layer 3: swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn)
	// Layer 4: V2 Fat Address with 2 token records (double swap: profile + post)
	realTx := "0x74fa41210000000000000000000000000000000000000000000000000000000000000060c42d26aa48365c5898e105a5f14751186dfefbd7705fde4e9c682294ed03a836a19cda8232888403688cb945c573e989107ac52836f4b7e73d21286ab4df7e0e00000000000000000000000000000000000000000000000000000000000003181e602c717b6b1343303e77e9dbfe45b37cf01144000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002c483362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000002b5e3af16b18800000000000000000000000000000000000000000000000000029331e6558f0e000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c800000000000000000000000000000000000000000000000000000000000000000000000000000000000001d5020200030b0d4361000000000000000000000000000000000000000000000000547963686f6e546f6b656e6275796d6561746f6b656e3032303a383961613637396637373237623739343932643030633432386331613730616339663863323865336165333036383432663035396132373365343834646339623a406b6b620000000000000000000000000000000000000000000000003839616136373966373732376237393439326430306334323863316137306163396638633238653361653330363834326630353961323733653438346463396233303137353a383961613637396637373237623739343932643030633432386331613730616339663863323865336165333036383432663035396132373365343834646339623a30313962613264632d616232362d373865622d623332312d38323333303531383537343333303137353a383961613637396637373237623739343932643030633432386331613730616339663863323865336165333036383432663035396132373365343834646339623a30313962613264632d616232362d373865622d623332312d3832333330353138353734337f777261db10993a64ea9453d61be47fc0f8bbd94277fd83ef0ba2fe7d96fca494567cb92d5b168900000000000000000000000000000000000000"

	t.Run("extract_swap_from_handleops", func(t *testing.T) {
		type result struct {
			Extracted string `db:"extract_swap_calldata_from_custom_handleops"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT extract_swap_calldata_from_custom_handleops($1)`, realTx)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.Contains(t, r.Extracted, "0x83362e17", "Should extract swap selector")
		require.True(t, len(r.Extracted) < len(realTx), "Extracted should be shorter")
	})

	t.Run("decode_base_token", func(t *testing.T) {
		type result struct {
			BaseToken *string `db:"base_token"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT decode_base_token_from_input($1) as base_token`, realTx)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.NotNil(t, r.BaseToken)

		expectedION := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		require.Equal(t, expectedION, *r.BaseToken, "Should decode ION token address")
	})

	t.Run("decode_to_token_v2_fat_address", func(t *testing.T) {
		type result struct {
			ToToken string `db:"decode_to_token_from_input"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT decode_to_token_from_input($1)`, realTx)
		require.NoError(t, err)
		require.NotNil(t, r)
		expectedExtAddr := "0:89aa679f7727b79492d00c428c1a70ac9f8c28e3ae306842f059a273e484dc9b:"
		require.Equal(t, expectedExtAddr, r.ToToken, "Should extract first token external address from V2 fat address")
	})

	t.Run("parse_custom_handleops_identifies_selector", func(t *testing.T) {
		type result struct {
			FunctionSelector string `db:"function_selector"`
		}
		r, err := storage.Get[result](ctx, db, `
			SELECT substring(REPLACE($1, '0x', '') from 1 for 8) as function_selector
		`, realTx)
		require.NoError(t, err)
		require.NotNil(t, r)

		require.Equal(t, "74fa4121", r.FunctionSelector, "Should identify handleOps selector")
	})

	t.Run("verify_fat_address_structure", func(t *testing.T) {
		type result struct {
			SwapData string `db:"swap_data"`
		}

		r, err := storage.Get[result](ctx, db, `
			SELECT extract_swap_calldata_from_custom_handleops($1) as swap_data
		`, realTx)

		require.NoError(t, err)
		require.NotNil(t, r)

		require.Contains(t, r.SwapData, "0x83362e17", "Should contain swap selector")
		require.Contains(t, r.SwapData, "020200", "Should contain V2 fat address header (version=02, records=02)")
		require.Contains(t, r.SwapData, "2c73996babf1a06c2c057177353293f7ca0907c8", "Should contain ION token address")
	})
}

func TestGetPlatformGroup(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()

	t.Run("ionconnect_prefix_a", func(t *testing.T) {
		type result struct {
			Platform *string `db:"platform"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT get_platform_group('a')::TEXT as platform`)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.NotNil(t, r.Platform)
		require.Equal(t, "ionconnect", *r.Platform, "Prefix 'a' should be ionconnect")
	})

	t.Run("ionconnect_prefix_b", func(t *testing.T) {
		type result struct {
			Platform *string `db:"platform"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT get_platform_group('b')::TEXT as platform`)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.NotNil(t, r.Platform)
		require.Equal(t, "ionconnect", *r.Platform, "Prefix 'b' should be ionconnect")
	})

	t.Run("xcom_prefix_z", func(t *testing.T) {
		type result struct {
			Platform *string `db:"platform"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT get_platform_group('z')::TEXT as platform`)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.NotNil(t, r.Platform)
		require.Equal(t, "xcom", *r.Platform, "Prefix 'z' should be xcom")
	})

	t.Run("xcom_prefix_w", func(t *testing.T) {
		type result struct {
			Platform *string `db:"platform"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT get_platform_group('w')::TEXT as platform`)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.NotNil(t, r.Platform)
		require.Equal(t, "xcom", *r.Platform, "Prefix 'w' should be xcom")
	})

	t.Run("numeric_prefix_returns_null", func(t *testing.T) {
		type result struct {
			Platform *string `db:"platform"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT get_platform_group('0')::TEXT as platform`)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.Nil(t, r.Platform, "Numeric prefix '0' should return NULL")
	})

	t.Run("unknown_prefix_returns_null", func(t *testing.T) {
		type result struct {
			Platform *string `db:"platform"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT get_platform_group('e')::TEXT as platform`)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.Nil(t, r.Platform, "Unknown prefix 'e' should return NULL")
	})

	t.Run("empty_prefix_returns_null", func(t *testing.T) {
		type result struct {
			Platform *string `db:"platform"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT get_platform_group('')::TEXT as platform`)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.Nil(t, r.Platform, "Empty prefix should return NULL")
	})
}

func TestUpdateMarketCapAndPosition(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()
	ctx := t.Context()
	ionAddress := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
	ionPriceUSD := 0.003

	_, err := storage.Exec(ctx, db, `
		INSERT INTO base_token_prices (token_address, token_symbol, price_usd, updated_at)
		VALUES ($1, 'ION', $2, NOW())
	`, ionAddress, ionPriceUSD)
	require.NoError(t, err)

	testUserAddr := "0x1234567890123456789012345678901234567890"
	testUserPubkey := "89aa679f7727b79492d00c428c1a70ac9f8c28e3ae306842f059a273e484dc9b"
	testUserExtAddr := "0:" + testUserPubkey + ":"
	testUserID := "test-user-id-123"

	_, err = storage.Exec(ctx, db, `
		INSERT INTO users (id, master_pubkey, content_author_id, external_address, username, display_name, avatar, platform_group, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'testuser', 'Test User', 'https://example.com/avatar.jpg', 'ionconnect', NOW(), NOW())
	`, testUserID, testUserPubkey, testUserAddr, testUserExtAddr)
	require.NoError(t, err)

	testTokenAddr := "0xdeadbeef00000000000000000000000000000001"
	testTokenExtAddr := testUserExtAddr
	testPairId := "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	totalSupply := "1000000000000000000000000" // 1,000,000 tokens

	_, err = storage.Exec(ctx, db, `
		INSERT INTO tokens (
			contract_address, external_address, title, ticker, base_token, pair_id,
			total_supply, type, platform, created_at, updated_at
		)
		VALUES ($1, $2, 'Test Token', 'TEST', $3, $4, $5, 'profile', 'ionconnect', NOW(), NOW())
	`, testTokenAddr, testTokenExtAddr, ionAddress, testPairId, totalSupply)
	require.NoError(t, err)

	t.Run("buy_creates_new_position", func(t *testing.T) {
		// BUY: user buys 980 tokens for 1000 ION
		blockTimestamp := "2024-01-01 12:00:00"
		direction := false                      // BUY
		inputAmount := "1000000000000000000000" // 1000 ION
		outputAmount := "980000000000000000000" // 980 tokens
		priceUSD := 0.003061224489795918        // (1000/980) * 0.003

		_, err := storage.Exec(ctx, db, `
			SELECT update_market_cap_and_position($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`,
			blockTimestamp,
			testUserAddr,
			testTokenAddr,
			testTokenExtAddr,
			direction,
			inputAmount,
			outputAmount,
			priceUSD,
			ionPriceUSD,
			totalSupply,
		)
		require.NoError(t, err)

		type tokenResult struct {
			PriceUSD     float64 `db:"price_usd"`
			MarketCapUSD float64 `db:"market_cap_usd"`
			MarketCapION float64 `db:"market_cap"`
			ImageURL     *string `db:"image_url"`
			Lookup       *string `db:"lookup"`
		}
		tr, err := storage.Get[tokenResult](ctx, db, `
			SELECT price_usd, market_cap_usd, market_cap, image_url, lookup
			FROM tokens
			WHERE contract_address = $1
		`, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, tr)
		require.InDelta(t, priceUSD, tr.PriceUSD, 0.000001, "Price USD should be updated")
		require.NotNil(t, tr.ImageURL, "Image URL should be set from user avatar")
		require.Equal(t, "https://example.com/avatar.jpg", *tr.ImageURL)
		require.NotNil(t, tr.Lookup, "Lookup should be populated")
		require.Contains(t, *tr.Lookup, "testuser", "Lookup should contain username")

		type positionResult struct {
			Amount           string  `db:"amount"`
			AvgBuyPriceUSD   float64 `db:"avg_buy_price_usd"`
			TotalInvestedUSD float64 `db:"total_invested_usd"`
			TotalRealizedUSD float64 `db:"total_realized_usd"`
		}
		pr, err := storage.Get[positionResult](ctx, db, `
			SELECT amount::TEXT, avg_buy_price_usd, total_invested_usd, total_realized_usd
			FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, testUserAddr, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, pr)
		require.Equal(t, outputAmount, pr.Amount, "Position amount should be 980 tokens")
		// v_cost_usd := (p_input_amount / 1e18) * p_ion_price_usd
		// v_cost_usd = (1000000000000000000000 / 1e18) * 0.003 = 1000 * 0.003 = 3 USD
		require.InDelta(t, 3.0, pr.TotalInvestedUSD, 0.000001, "Total invested = (1000 * 10^18 / 1e18) * 0.003 USD = 3 USD")
		require.InDelta(t, priceUSD, pr.AvgBuyPriceUSD, 0.000001, "Avg buy price should match token price")
		require.Equal(t, 0.0, pr.TotalRealizedUSD, "Realized USD should be 0 for buy")
	})

	t.Run("second_buy_updates_position", func(t *testing.T) {
		// Second BUY: user buys another 490 tokens for 500 ION
		blockTimestamp := "2024-01-01 13:00:00"
		direction := false                      // BUY
		inputAmount := "500000000000000000000"  // 500 ION
		outputAmount := "490000000000000000000" // 490 tokens
		priceUSD := 0.003061224489795918

		_, err := storage.Exec(ctx, db, `
			SELECT update_market_cap_and_position($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`,
			blockTimestamp,
			testUserAddr,
			testTokenAddr,
			testTokenExtAddr,
			direction,
			inputAmount,
			outputAmount,
			priceUSD,
			ionPriceUSD,
			totalSupply,
		)
		require.NoError(t, err)

		type positionResult struct {
			Amount           string  `db:"amount"`
			TotalInvestedUSD float64 `db:"total_invested_usd"`
		}
		pr, err := storage.Get[positionResult](ctx, db, `
			SELECT amount::TEXT, total_invested_usd
			FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, testUserAddr, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, pr)
		// Total amount = 980 + 490 = 1470 tokens
		require.Equal(t, "1470000000000000000000", pr.Amount, "Position should accumulate: 980 + 490 = 1470")
		// Total invested = 3 + 1.5 = 4.5 USD
		require.InDelta(t, 4.5, pr.TotalInvestedUSD, 0.000001, "Total invested should accumulate: 3 + 1.5 = 4.5 USD")
	})

	t.Run("sell_updates_position_and_realizes_pnl", func(t *testing.T) {
		// SELL: user sells 500 tokens for 520 ION (profit!)
		blockTimestamp := "2024-01-01 14:00:00"
		direction := true                       // SELL
		inputAmount := "500000000000000000000"  // 500 tokens
		outputAmount := "520000000000000000000" // 520 ION
		priceUSD := 0.00312                     // (520/500) * 0.003

		_, err := storage.Exec(ctx, db, `
			SELECT update_market_cap_and_position($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`,
			blockTimestamp,
			testUserAddr,
			testTokenAddr,
			testTokenExtAddr,
			direction,
			inputAmount,
			outputAmount,
			priceUSD,
			ionPriceUSD,
			totalSupply,
		)
		require.NoError(t, err)

		type positionResult struct {
			Amount           string  `db:"amount"`
			TotalRealizedUSD float64 `db:"total_realized_usd"`
		}
		pr, err := storage.Get[positionResult](ctx, db, `
			SELECT amount::TEXT, total_realized_usd
			FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, testUserAddr, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, pr)
		// Remaining amount = 1470 - 500 = 970 tokens
		require.Equal(t, "970000000000000000000", pr.Amount, "Position should decrease: 1470 - 500 = 970")
		// Realized = (520 * 10^18 / 1e18) * 0.003 USD = 520 * 0.003 = 1.56 USD
		require.InDelta(t, 1.56, pr.TotalRealizedUSD, 0.000001, "Realized USD should be (520 * 10^18 / 1e18) * 0.003 = 1.56 USD")
	})

	t.Run("sell_all_zeros_position", func(t *testing.T) {
		// SELL ALL: user sells remaining 970 tokens
		blockTimestamp := "2024-01-01 15:00:00"
		direction := true                        // SELL
		inputAmount := "970000000000000000000"   // 970 tokens
		outputAmount := "1000000000000000000000" // 1000 ION
		priceUSD := 0.003092783505154639

		_, err := storage.Exec(ctx, db, `
			SELECT update_market_cap_and_position($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`,
			blockTimestamp,
			testUserAddr,
			testTokenAddr,
			testTokenExtAddr,
			direction,
			inputAmount,
			outputAmount,
			priceUSD,
			ionPriceUSD,
			totalSupply,
		)
		require.NoError(t, err)

		type positionResult struct {
			Amount           string  `db:"amount"`
			TotalRealizedUSD float64 `db:"total_realized_usd"`
		}
		pr, err := storage.Get[positionResult](ctx, db, `
			SELECT amount::TEXT, total_realized_usd
			FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, testUserAddr, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, pr)
		require.Equal(t, "0", pr.Amount, "Position should be zero after selling all")
		// Total realized = 1.56 + 3.0 = 4.56 USD
		require.InDelta(t, 4.56, pr.TotalRealizedUSD, 0.000001, "Total realized should accumulate: 1.56 + 3.0 = 4.56 USD")
	})

	t.Run("profile_token_updates_base_token_price", func(t *testing.T) {
		type basePriceResult struct {
			Count int `db:"count"`
		}
		bpr, err := storage.Get[basePriceResult](ctx, db, `
			SELECT COUNT(*) as count
			FROM base_token_prices
			WHERE token_address = $1
		`, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, bpr)
		require.Equal(t, 0, bpr.Count, "update_market_cap_and_position should NOT update base_token_prices directly")
	})

	t.Run("verify_image_url_and_lookup_populated", func(t *testing.T) {
		type tokenResult struct {
			ImageURL *string `db:"image_url"`
			Lookup   *string `db:"lookup"`
		}
		tr, err := storage.Get[tokenResult](ctx, db, `
			SELECT image_url, lookup
			FROM tokens
			WHERE contract_address = $1
		`, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, tr)
		require.NotNil(t, tr.ImageURL, "image_url should be set")
		require.Equal(t, "https://example.com/avatar.jpg", *tr.ImageURL, "image_url should be from user avatar")
		require.NotNil(t, tr.Lookup, "lookup should be populated")
		require.Contains(t, *tr.Lookup, "deadbeef", "lookup should contain contract address")
		require.Contains(t, *tr.Lookup, "test", "lookup should contain ticker")
		require.Contains(t, *tr.Lookup, "testuser", "lookup should contain username")
		require.Contains(t, *tr.Lookup, "test user", "lookup should contain display name (lowercased)")
	})

	t.Run("image_url_not_overwritten_on_subsequent_buys", func(t *testing.T) {
		customImageURL := "https://custom.com/token-image.png"
		_, err := storage.Exec(ctx, db, `
			UPDATE tokens
			SET image_url = $1
			WHERE contract_address = $2
		`, customImageURL, testTokenAddr)
		require.NoError(t, err)

		newUserAddr := "0xabcdef0000000000000000000000000000000000"
		newUserPubkey := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
		newUserExtAddr := "0:" + newUserPubkey + ":"
		newUserID := "new-user-id-456"

		_, err = storage.Exec(ctx, db, `
			INSERT INTO users (id, master_pubkey, content_author_id, external_address, username, display_name, avatar, platform_group, created_at, updated_at)
			VALUES ($1, $2, $3, $4, 'newuser', 'New User', 'https://example.com/new-avatar.jpg', 'ionconnect', NOW(), NOW())
		`, newUserID, newUserPubkey, newUserAddr, newUserExtAddr)
		require.NoError(t, err)

		blockTimestamp := "2024-01-01 16:00:00"
		direction := false                     // BUY
		inputAmount := "100000000000000000000" // 100 ION
		outputAmount := "98000000000000000000" // 98 tokens
		priceUSD := 0.003061224489795918

		_, err = storage.Exec(ctx, db, `
			SELECT update_market_cap_and_position($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`,
			blockTimestamp,
			newUserAddr,
			testTokenAddr,
			testTokenExtAddr,
			direction,
			inputAmount,
			outputAmount,
			priceUSD,
			ionPriceUSD,
			totalSupply,
		)
		require.NoError(t, err)

		type tokenResult struct {
			ImageURL *string `db:"image_url"`
		}
		tr, err := storage.Get[tokenResult](ctx, db, `
			SELECT image_url
			FROM tokens
			WHERE contract_address = $1
		`, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, tr)
		require.NotNil(t, tr.ImageURL)
		require.Equal(t, customImageURL, *tr.ImageURL, "image_url should NOT be overwritten on subsequent buys")
	})
}

func TestToInt256(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()

	t.Run("positive_values_unchanged", func(t *testing.T) {
		type result struct {
			Value string `db:"value"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT to_int256(1000)::TEXT as value`)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.Equal(t, "1000", r.Value, "Positive values should remain unchanged")
	})

	t.Run("max_positive_int256", func(t *testing.T) {
		// 2^255 - 1 (max positive int256)
		maxPositive := "57896044618658097711785492504343953926634992332820282019728792003956564819967"
		type result struct {
			Value string `db:"value"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT to_int256($1::NUMERIC)::TEXT as value`, maxPositive)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.Equal(t, maxPositive, r.Value, "Max positive int256 should remain unchanged")
	})

	t.Run("converts_large_uint256_to_negative", func(t *testing.T) {
		// 2^255 should be converted to -2^255
		uint256Value := "57896044618658097711785492504343953926634992332820282019728792003956564819968" // 2^255
		expectedInt256 := "-57896044618658097711785492504343953926634992332820282019728792003956564819968"
		type result struct {
			Value string `db:"value"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT to_int256($1::NUMERIC)::TEXT as value`, uint256Value)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.Equal(t, expectedInt256, r.Value, "2^255 should be converted to negative")
	})

	t.Run("converts_max_uint256_to_minus_one", func(t *testing.T) {
		// 2^256 - 1 (max uint256) should be converted to -1
		maxUint256 := "115792089237316195423570985008687907853269984665640564039457584007913129639935"
		expectedInt256 := "-1"
		type result struct {
			Value string `db:"value"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT to_int256($1::NUMERIC)::TEXT as value`, maxUint256)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.Equal(t, expectedInt256, r.Value, "Max uint256 should be converted to -1")
	})

	t.Run("zero_unchanged", func(t *testing.T) {
		type result struct {
			Value string `db:"value"`
		}
		r, err := storage.Get[result](ctx, db, `SELECT to_int256(0)::TEXT as value`)
		require.NoError(t, err)
		require.NotNil(t, r)
		require.Equal(t, "0", r.Value, "Zero should remain zero")
	})
}

func TestUpdateBaseTokenPrice(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()

	testTokenAddr := "0xprofiletoken000000000000000000000000001"
	testTokenTicker := "PROF"

	t.Run("creates_new_base_token_price", func(t *testing.T) {
		priceUSD := 0.005

		_, err := storage.Exec(ctx, db, `
			SELECT update_base_token_price($1, $2, $3)
		`, testTokenAddr, testTokenTicker, priceUSD)
		require.NoError(t, err)

		type priceResult struct {
			TokenAddress string  `db:"token_address"`
			TokenSymbol  string  `db:"token_symbol"`
			PriceUSD     float64 `db:"price_usd"`
		}
		pr, err := storage.Get[priceResult](ctx, db, `
			SELECT token_address, token_symbol, price_usd
			FROM base_token_prices
			WHERE token_address = $1
		`, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, pr)
		require.Equal(t, testTokenAddr, pr.TokenAddress)
		require.Equal(t, testTokenTicker, pr.TokenSymbol)
		require.InDelta(t, priceUSD, pr.PriceUSD, 0.000001)
		type historyResult struct {
			Count int `db:"count"`
		}
		hr, err := storage.Get[historyResult](ctx, db, `
			SELECT COUNT(*) as count
			FROM base_token_price_history
			WHERE token_address = $1 AND price_usd = $2
		`, testTokenAddr, priceUSD)
		require.NoError(t, err)
		require.NotNil(t, hr)
		require.Equal(t, 1, hr.Count, "Price history should have 1 record")
	})

	t.Run("updates_existing_price", func(t *testing.T) {
		newPriceUSD := 0.007

		_, err := storage.Exec(ctx, db, `
			SELECT update_base_token_price($1, $2, $3)
		`, testTokenAddr, testTokenTicker, newPriceUSD)
		require.NoError(t, err)

		type priceResult struct {
			PriceUSD float64 `db:"price_usd"`
		}
		pr, err := storage.Get[priceResult](ctx, db, `
			SELECT price_usd
			FROM base_token_prices
			WHERE token_address = $1
		`, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, pr)
		require.InDelta(t, newPriceUSD, pr.PriceUSD, 0.000001, "Price should be updated")
		type historyResult struct {
			Count int `db:"count"`
		}
		hr, err := storage.Get[historyResult](ctx, db, `
			SELECT COUNT(*) as count
			FROM base_token_price_history
			WHERE token_address = $1
		`, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, hr)
		require.Equal(t, 2, hr.Count, "Price history should have 2 records (old + new)")
	})

	t.Run("does_not_create_duplicate_history_for_same_price", func(t *testing.T) {
		samePriceUSD := 0.007

		_, err := storage.Exec(ctx, db, `
			SELECT update_base_token_price($1, $2, $3)
		`, testTokenAddr, testTokenTicker, samePriceUSD)
		require.NoError(t, err)

		type historyResult struct {
			Count int `db:"count"`
		}
		hr, err := storage.Get[historyResult](ctx, db, `
			SELECT COUNT(*) as count
			FROM base_token_price_history
			WHERE token_address = $1
		`, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, hr)
		require.Equal(t, 2, hr.Count, "Price history should still have 2 records (no duplicate for same price)")
	})

	t.Run("creates_history_when_price_changes_again", func(t *testing.T) {
		anotherPriceUSD := 0.009

		_, err := storage.Exec(ctx, db, `
			SELECT update_base_token_price($1, $2, $3)
		`, testTokenAddr, testTokenTicker, anotherPriceUSD)
		require.NoError(t, err)

		type historyResult struct {
			Count int `db:"count"`
		}
		hr, err := storage.Get[historyResult](ctx, db, `
			SELECT COUNT(*) as count
			FROM base_token_price_history
			WHERE token_address = $1
		`, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, hr)
		require.Equal(t, 3, hr.Count, "Price history should have 3 records now")
		type allPricesResult struct {
			Prices []float64 `db:"prices"`
		}
		apr, err := storage.Get[allPricesResult](ctx, db, `
			SELECT array_agg(price_usd ORDER BY created_at) as prices
			FROM base_token_price_history
			WHERE token_address = $1
		`, testTokenAddr)
		require.NoError(t, err)
		require.NotNil(t, apr)
		require.Len(t, apr.Prices, 3, "Should have 3 price records")
		require.InDelta(t, 0.005, apr.Prices[0], 0.000001, "First price: 0.005")
		require.InDelta(t, 0.007, apr.Prices[1], 0.000001, "Second price: 0.007")
		require.InDelta(t, 0.009, apr.Prices[2], 0.000001, "Third price: 0.009")
	})
}

func TestProcessPairRegistered(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()
	ctx := t.Context()

	const (
		testTokenAddr     = "0x1234567890abcdef1234567890abcdef12345678"
		testExternalAddr  = "a:testuser123"
		testPlatform      = "ionconnect"
		testTokenType     = "profile"
		testBaseTokenAddr = "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		testPairID        = "0x51ea17cf5c8e1a25a0c9c22ff9208679b60c945cd7057c2607d35a9b110526c0"
		testPriceModel    = "0xdead000000000000000000000000000000000000"
		testStartPrice    = "1000000000000000000"
		testEndPrice      = "2000000000000000000"
	)

	_, err := storage.Exec(ctx, db, `
		INSERT INTO tokens (
			created_at, updated_at, contract_address, external_address, 
			platform, ticker, title, total_supply, type
		) VALUES (
			NOW(), NOW(), $1, $2, $3, 'TEST', 'Test Token', 1000000, $4
		)
	`, testTokenAddr, testExternalAddr, testPlatform, testTokenType)
	require.NoError(t, err)

	t.Run("process_pair_registered_with_all_params", func(t *testing.T) {
		topics := fmt.Sprintf(`{"%s", "%s", "0x000000000000000000000000%s", "0x000000000000000000000000%s"}`,
			"0x872521cd21d976cd52c101bb81804e331c479f7895644ae16140b559222fda5c", // PairRegistered signature
			testPairID,
			testBaseTokenAddr[2:], // Remove 0x
			testTokenAddr[2:],     // Remove 0x
		)
		data := fmt.Sprintf("0x000000000000000000000000%s%064s%064s",
			testPriceModel[2:], // priceModel (remove 0x, pad to 32 bytes)
			testStartPrice[2:], // startPrice (hex, already 64 chars)
			testEndPrice[2:],   // endPrice (hex, already 64 chars)
		)
		_, err := storage.Exec(ctx, db, `SELECT process_pair_registered($1::TEXT[], $2::TEXT, NOW()::TIMESTAMP)`, topics, data)
		require.NoError(t, err)

		type tokenResult struct {
			PairID    string `db:"pair_id"`
			BaseToken string `db:"base_token"`
		}
		result, err := storage.Get[tokenResult](ctx, db, `
			SELECT pair_id, base_token 
			FROM tokens 
			WHERE LOWER(contract_address) = LOWER($1)
		`, testTokenAddr)
		require.NoError(t, err)
		require.Equal(t, strings.ToLower(testPairID), strings.ToLower(result.PairID))
		require.Equal(t, strings.ToLower(testBaseTokenAddr), strings.ToLower(result.BaseToken))
	})

	t.Run("process_pair_registered_insufficient_topics", func(t *testing.T) {
		topics := `{"0x872521cd21d976cd52c101bb81804e331c479f7895644ae16140b559222fda5c", "0x1234"}`
		data := "0x"

		_, err := storage.Exec(ctx, db, `SELECT process_pair_registered($1::TEXT[], $2::TEXT, NOW()::TIMESTAMP)`, topics, data)
		require.NoError(t, err)
	})

	t.Run("process_pair_registered_nonexistent_token", func(t *testing.T) {
		const nonExistentToken = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		topics := fmt.Sprintf(`{"%s", "%s", "0x000000000000000000000000%s", "0x000000000000000000000000%s"}`,
			"0x872521cd21d976cd52c101bb81804e331c479f7895644ae16140b559222fda5c",
			testPairID,
			testBaseTokenAddr[2:],
			nonExistentToken[2:],
		)
		data := "0x"

		_, err := storage.Exec(ctx, db, `SELECT process_pair_registered($1::TEXT[], $2::TEXT, NOW()::TIMESTAMP)`, topics, data)
		require.NoError(t, err)
	})
}
