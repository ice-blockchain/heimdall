// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
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
