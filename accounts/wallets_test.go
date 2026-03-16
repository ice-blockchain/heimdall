// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"io"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/coins"
	indexer "github.com/ice-blockchain/heimdall/ion-indexer"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/connectors/storage/v2/fixture"
	"github.com/ice-blockchain/wintr/time"
)

type mockWalletClient struct {
	mockedWallets map[string]dfns.Wallet
}

type mockIONIndexer struct {
	nftsIndexerTriggered bool
	balanceTriggered     map[string]struct{}
}
type mockAuth struct {
	userId   string
	username string
}

func (m *mockAuth) UserID() string {
	return m.userId
}
func (m *mockAuth) Username() string {
	return m.username
}

func newMockedWalletClient() interface {
	dfns.DfnsClient
	Coins
} {
	wallets := map[string]dfns.Wallet{
		"wa-wallet1": map[string]any{
			"id":          "wa-wallet1",
			"network":     "EthereumSepolia",
			"address":     "addr1",
			"name":        "test wallet1",
			"dateCreated": "2026-02-10T14:51:00.790Z",
			"signingKey": map[string]any{
				"publicKey":   "e2375c8c9e87bfcd0be8f29d76c818cabacd51584f72cb2222d49a13b036d84d3d",
				"id":          "key",
				"scheme":      "ECDSA",
				"delegatedTo": "userID",
				"curve":       "secp256k1",
			},
			"assets": []dfns.Asset{
				map[string]any{
					"kind":     "Erc20",
					"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
					"symbol":   "USDC",
					"decimals": 6,
					"verified": true,
					"balance":  "1000000",
				},
				map[string]any{
					"kind":     "Erc20",
					"contract": "0x79f05c263055ba20ee0e814acd117c20caa10e0c",
					"symbol":   "ICE",
					"decimals": 18,
					"verified": true,
					"balance":  "1000000",
				},
			},
			"nfts": []dfns.NFT{
				{
					"kind":     "Erc721",
					"contract": "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d",
					"tokenId":  "8500",
					"symbol":   "BAYC",
					"tokenUri": "ipfs://QmeSjSinHpPnmXmspMjwiXyN6zS4E9zccariGR3jxcaWtq/8500",
				},
			},
		},
		"wa-wallet2": map[string]any{
			"id":          "wa-wallet2",
			"network":     "BscTestnet",
			"address":     "addr2",
			"name":        "test wallet2",
			"dateCreated": "2026-02-10T14:51:00.790Z",
			"signingKey": map[string]any{
				"publicKey":   "e2375c8c9e87bfcd0be8f29d76c818cabacd51584f72cb2222d49a13b036d84d3d",
				"id":          "key",
				"scheme":      "ECDSA",
				"delegatedTo": "userID",
				"curve":       "secp256k1",
			},
			"assets": []dfns.Asset{
				map[string]any{
					"kind":     "Erc20",
					"contract": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
					"symbol":   "USDC",
					"decimals": 6,
					"verified": true,
					"balance":  "2000000",
				},
				map[string]any{
					"kind":     "Erc20",
					"contract": "0x000000000000000000000000000000000000dead",
					"symbol":   "USDC",
					"decimals": 6,
					"verified": false,
					"balance":  "2222222",
				},
			},
			"nfts": []dfns.NFT{
				{
					"kind":     "Erc721",
					"contract": "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d",
					"tokenId":  "8501",
					"symbol":   "BAYC",
					"tokenUri": "ipfs://QmeSjSinHpPnmXmspMjwiXyN6zS4E9zccariGR3jxcaWtq/8501",
				},
			},
		},
		"wa-wallet3": map[string]any{
			"id":          "wa-wallet3",
			"network":     "IonTestnet",
			"address":     "addr3",
			"name":        "test wallet3",
			"dateCreated": "2026-02-10T14:51:00.790Z",
			"signingKey": map[string]any{
				"id":          "key",
				"publicKey":   "masterkey",
				"scheme":      "ECDSA",
				"delegatedTo": "userID",
				"curve":       "secp256k1",
			},
			"assets": []dfns.Asset{
				map[string]any{
					"kind":     "Native",
					"symbol":   "ice",
					"decimals": 9,
					"verified": true,
					"balance":  "1000000000000000000",
				},
			},
			"nfts": []dfns.NFT{},
		},
		"wa-tokenized-community": map[string]any{
			"id":          "wa-tokenized-community",
			"network":     "BscTestnet",
			"address":     "addr-tokenized-community",
			"name":        "tokenized community wallet",
			"dateCreated": "2026-02-10T14:51:00.790Z",
			"signingKey": map[string]any{
				"id":          "key",
				"publicKey":   "pubkey",
				"scheme":      "ECDSA",
				"delegatedTo": "userID",
				"curve":       "secp256k1",
			},
			"assets": []dfns.Asset{
				map[string]any{
					"balance":  "1113871018693693333332",
					"contract": "0xbb88c364c759b2b42423b71f043212085d4cdeb0",
					"decimals": 18,
					"kind":     "Erc20",
					"symbol":   "non-updated-symbol",
				},
			},
			"nfts": []dfns.NFT{},
		},
	}
	return &mockWalletClient{mockedWallets: wallets}
}

func (m *mockWalletClient) ProxyCall(ctx context.Context, rw http.ResponseWriter, r *http.Request) (status int, respBody io.Reader) {
	panic("TODO")
}

func (m *mockWalletClient) StartDelegatedRecovery(ctx context.Context, username string, credentialId string) (*dfns.StartedDelegatedRecovery, error) {
	panic("TODO")
}

func (m *mockWalletClient) GetLoginChallenge(ctx context.Context, username string) (*dfns.LoginChallenge, error) {
	panic("TODO")
}

func (m *mockWalletClient) InitRegistration(ctx context.Context, identityKeyName string) (*dfns.RegistrationChallenge, error) {
	panic("TODO")
}

func (m *mockWalletClient) CompleteRegistrationWithWallets(ctx context.Context, credentials *dfns.Credentials) (dfns.CompletedRegistration, error) {
	panic("TODO")
}

func (m *mockWalletClient) GetUser(ctx context.Context, userID string) (*dfns.User, error) {
	panic("TODO")
}

func (m *mockWalletClient) VerifyWebhookSecret(now *time.Time, eventSignature string, payload []byte) error {
	return nil
}

func (m *mockWalletClient) RegisterPostProxyCallback(url string, cb func(req *http.Request, now *time.Time, res map[string]any) error) {
	panic("TODO")
}

func (m *mockWalletClient) ListWallets(ctx context.Context, userID string) ([]dfns.Wallet, error) {
	res := []dfns.Wallet{}
	for _, w := range m.mockedWallets {
		res = append(res, w)
	}
	return res, nil
}

func (m *mockWalletClient) GetWallet(ctx context.Context, walletID string) (*dfns.Wallet, error) {
	w := m.mockedWallets[walletID]
	return &w, nil
}

func (m *mockWalletClient) CreateWallet(ctx context.Context, network, name string) (*dfns.Wallet, error) {
	panic("TODO")
}

func (m *mockWalletClient) ListAssets(ctx context.Context, walletID string) (*dfns.Assets, error) {
	stdlibtime.Sleep(3 * stdlibtime.Second)
	w := m.mockedWallets[walletID]
	return &dfns.Assets{
		Assets:   w["assets"].([]dfns.Asset),
		Network:  w["network"].(string),
		WalletID: walletID,
	}, nil
}

func (m *mockWalletClient) ListNFTs(ctx context.Context, walletID string) (*dfns.NFTs, error) {
	w := m.mockedWallets[walletID]
	nfts := w["nfts"].([]dfns.NFT)
	network := w["network"].(string)
	if strings.EqualFold(network, "iontestnet") {
		derr := &dfns.DfnsInternalError{
			Context: nil,
			Message: "IonTestnet does not support NFT balances",
		}
		derr.HTTPStatus = http.StatusBadRequest
		return nil, derr
	}
	return &dfns.NFTs{
		WalletID: walletID,
		Network:  network,
		NFTs:     nfts,
	}, nil
}

func (m *mockWalletClient) ImportTokenizedCommunitiesCoin(ctx context.Context, coin coins.TokenAnalyticsToken) (*coins.Coin, error) {
	return nil, nil
}

func (m *mockWalletClient) SecurePaymentConfirmation(ctx context.Context, userID, network string, wallet dfns.Wallet, body map[string]string) (tmplData any, err error) {
	panic("TODO")
}

func (m *mockWalletClient) GetCoinsOfSymbolGroup(ctx context.Context, symbolGroups []string) ([]*coins.Coin, error) {
	return nil, nil
}
func (m *mockWalletClient) GetNativeCoinForNetwork(ctx context.Context, network string) (*coins.Coin, error) {
	return nil, nil
}
func (m *mockWalletClient) GetFees(network string) *coins.Fee {
	return nil
}
func (m *mockWalletClient) GetNetworkFees(context.Context, string) (*dfns.FeeWithPriority, error) {
	return nil, errors.New("not implemented")
}
func (m *mockWalletClient) BroadcastTransactionFromWallet(ctx context.Context, walletId string, transactionData *TransactionPayload) (*TransactionResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockWalletClient) GetAllNetworks() []*coins.Network {
	return nil
}
func (m *mockWalletClient) ImportNFTs(ctx context.Context, network string, nft []coins.WalletNFT) ([]*coins.NFT, error) {
	res := []*coins.NFT{}
	for _, n := range nft {
		res = append(res, &coins.NFT{
			WalletNFT: n,
		})
	}
	return res, nil
}

func (m *mockIONIndexer) ListNFTs(ctx context.Context, walletAddr string, paginationToken string, limit uint64) ([]coins.WalletNFT, *string, error) {
	m.nftsIndexerTriggered = true
	return []coins.WalletNFT{}, nil, nil
}
func (m *mockIONIndexer) GetBalance(ctx context.Context, walletAddr string) ([]indexer.Asset, error) {
	m.balanceTriggered[walletAddr] = struct{}{}
	return []indexer.Asset{map[string]any{
		"kind":     "Native",
		"decimals": 9,
		"balance":  "1000000000000000000",
		"symbol":   "ION",
		"verified": true,
	}}, nil
}

var testPgContainer *fixture.Container

func helperCreateDBWithConnString(t *testing.T) (*storage.DB, string, func()) {
	t.Helper()

	connString, release := testPgContainer.MustTempDB(t.Context())
	db := storage.MustConnectWithCfg(t.Context(),
		&storage.Cfg{
			PrimaryURL:   connString,
			ReplicaURLs:  []string{connString},
			RunDDL:       true,
			IgnoreGlobal: true,
		},
		storage.NewStringDDL(ddl),
	)
	require.NotNil(t, db)

	return db, connString, func() {
		db.Close()
		release()
	}
}
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

func TestFetchWalletInfoForCoinsAggregation(t *testing.T) {
	cl := newMockedWalletClient()
	ionIndexer := &mockIONIndexer{
		balanceTriggered: map[string]struct{}{},
	}
	db, _, release := helperCreateDBWithConnString(t)
	defer release()
	a := &accounts{
		delegatedRPClient: cl,
		coinsRepo:         cl,
		indexer:           ionIndexer,
		db:                db,
		cfg:               &config{DefaultCoinsInWalletView: []string{"ion"}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*stdlibtime.Second)
	ctx = context.WithValue(ctx, "requestingUserCtxValueKey", &mockAuth{userId: "userID"})
	defer cancel()
	wallet1, wallet2, wallet3 := "wa-wallet1", "wa-wallet2", "wa-wallet3"
	tcAddress := "0:abcd:"
	tcType := "profile"
	wallets, err := cl.ListWallets(ctx, "userID")
	require.NoError(t, err)
	_, err = a.insertIdentityKeyNameWithPubKeyAndVisitorID(ctx, time.Now(), "userID", "userKeyName", "master", "", "", "")
	require.NoError(t, err)
	for _, w := range wallets {
		require.NoError(t, a.storeUserWallet(ctx, "userID", w))
	}
	aggregatedCoins, nfts, _, err := a.fetchWalletInfoForCoins(ctx, "userID", []*CoinMapping{
		{
			Coin: &coins.Coin{
				ID:              "ice_id",
				Symbol:          "ice",
				Network:         "EthereumSepolia",
				ContractAddress: "0x79f05c263055ba20ee0e814acd117c20caa10e0c",
				Native:          false,
			},
			WalletID: &wallet1,
			CoinID:   "ice_id",
		},
		{
			Coin: &coins.Coin{
				ID:              "ice_ion_id",
				Symbol:          "ION",
				Network:         "IonTestNet",
				ContractAddress: "",
				Native:          true,
			},
			WalletID: &wallet3,
			CoinID:   "ice_ion_id",
		},
		{
			Coin: &coins.Coin{
				ID:              "usdc_id",
				Symbol:          "usdc",
				Network:         "EthereumSepolia",
				ContractAddress: "0x79f05c263055ba20ee0e814acd117c20caa10e0c",
				Native:          true,
			},
			WalletID: &wallet1,
			CoinID:   "usdc_id",
		},
		{
			Coin: &coins.Coin{
				ID:              "usdc_on_bsc_id",
				Symbol:          "usdc",
				Network:         "BscTestnet",
				ContractAddress: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
				Native:          false,
			},
			WalletID: &wallet2,
			CoinID:   "usdc_on_bsc_id",
		},
		{
			Coin: &coins.Coin{
				ID:                                "usdc_on_bsc_bogus_from_tc",
				Symbol:                            "usdc",
				Network:                           "BscTestnet",
				ContractAddress:                   "0x000000000000000000000000000000000000dead",
				TokenizedCommunityExternalAddress: &tcAddress,
				TokenizedCommunityTokenType:       &tcType,
			},
			WalletID: &wallet2,
			CoinID:   "usdc_on_bsc_bogus_from_tc",
		},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, nfts)
	require.NotEmpty(t, aggregatedCoins)
	require.Len(t, aggregatedCoins, 4)
	require.Contains(t, maps.Keys(aggregatedCoins), "usdc", "ice", "ion", "0x000000000000000000000000000000000000dead")
	assetUSDCOnBSC := dfns.Asset(map[string]any{
		"kind":     "Erc20",
		"contract": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
		"symbol":   "USDC",
		"decimals": 6,
		"verified": true,
		"balance":  "2000000",
	})
	assetUSDCOnBSCBogusFromTC := dfns.Asset(map[string]any{
		"kind":     "Erc20",
		"contract": "0x000000000000000000000000000000000000dead",
		"symbol":   "USDC",
		"decimals": 6,
		"verified": false,
		"balance":  "2222222",
	})
	assetUSDCOnSepolia := dfns.Asset(map[string]any{
		"kind":     "Erc20",
		"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"symbol":   "USDC",
		"decimals": 6,
		"verified": true,
		"balance":  "1000000",
	})
	assetTokenizedCommunityCoin := dfns.Asset(map[string]any{
		"balance":  "1113871018693693333332",
		"contract": "0xbb88c364c759b2b42423b71f043212085d4cdeb0",
		"decimals": 18,
		"kind":     "Erc20",
		"symbol":   "non-updated-symbol",
	})

	aggregatedCoinsUSDC, ok := aggregatedCoins["usdc"]
	require.True(t, ok)
	sort.Slice(aggregatedCoinsUSDC.Wallets, func(i, j int) bool {
		return aggregatedCoinsUSDC.Wallets[i].Network > aggregatedCoinsUSDC.Wallets[j].Network
	})

	require.EqualValues(t,
		&CoinAggregation{
			TotalBalance: big.NewInt(3000000),
			Wallets: []*CoinInWallet{
				{
					Asset:    &assetUSDCOnSepolia,
					WalletID: "wa-wallet1",
					Network:  "EthereumSepolia",
					CoinID:   "usdc_id",
				},
				{
					Asset:    &assetUSDCOnBSC,
					WalletID: "wa-wallet2",
					Network:  "BscTestnet",
					CoinID:   "usdc_on_bsc_id",
				},
			},
		},
		aggregatedCoinsUSDC,
	)
	aggregatedCoinsUSDCBogusFromTC, ok := aggregatedCoins["0x000000000000000000000000000000000000dead"]
	require.True(t, ok)

	require.EqualValues(t,
		&CoinAggregation{
			TotalBalance: big.NewInt(2222222),
			Wallets: []*CoinInWallet{
				{
					Asset:    &assetUSDCOnBSCBogusFromTC,
					WalletID: "wa-wallet2",
					Network:  "BscTestnet",
					CoinID:   "usdc_on_bsc_bogus_from_tc",
				},
			},
		},
		aggregatedCoinsUSDCBogusFromTC,
	)

	assetION := dfns.Asset(map[string]any{
		"kind":     "Native",
		"symbol":   "ION",
		"decimals": 9,
		"verified": true,
		"balance":  "1000000000000000000",
	})
	require.EqualValues(t, &CoinAggregation{
		TotalBalance: big.NewInt(1000000000000000000),
		Wallets: []*CoinInWallet{
			{
				Asset:    &assetION,
				WalletID: "wa-wallet3",
				Network:  "IonTestnet",
				CoinID:   "ice_ion_id",
			},
		},
	}, aggregatedCoins["ion"])
	assetICE := dfns.Asset(map[string]any{
		"kind":     "Erc20",
		"contract": "0x79f05c263055ba20ee0e814acd117c20caa10e0c",
		"symbol":   "ICE",
		"decimals": 18,
		"verified": true,
		"balance":  "1000000",
	})
	require.EqualValues(t, &CoinAggregation{
		TotalBalance: big.NewInt(1000000),
		Wallets: []*CoinInWallet{
			{
				Asset:    &assetICE,
				WalletID: "wa-wallet1",
				Network:  "EthereumSepolia",
				CoinID:   "ice_id",
			},
		},
	}, aggregatedCoins["ice"])

	require.Len(t, nfts, 2)
	walletNfts := make([]coins.WalletNFT, 0, len(nfts))
	for _, n := range nfts {
		walletNfts = append(walletNfts, n.WalletNFT)
	}
	require.Contains(t, walletNfts, coins.WalletNFT(map[string]any{
		"kind":     "Erc721",
		"contract": "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d",
		"tokenId":  "8500",
		"symbol":   "BAYC",
		"tokenUri": "ipfs://QmeSjSinHpPnmXmspMjwiXyN6zS4E9zccariGR3jxcaWtq/8500",
	}))
	require.Contains(t, walletNfts, coins.WalletNFT(map[string]any{
		"kind":     "Erc721",
		"contract": "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d",
		"tokenId":  "8501",
		"symbol":   "BAYC",
		"tokenUri": "ipfs://QmeSjSinHpPnmXmspMjwiXyN6zS4E9zccariGR3jxcaWtq/8501",
	}))

	require.True(t, ionIndexer.nftsIndexerTriggered)
	require.Len(t, ionIndexer.balanceTriggered, 1)
	_, balanceWasTriggeredForWallet3 := ionIndexer.balanceTriggered["addr3"]
	require.True(t, balanceWasTriggeredForWallet3)
	walletTokenizedCommunity := "wa-tokenized-community"
	t.Run("coins is from tokenized comminity and user changed his username (symbol)", func(t *testing.T) {
		tokenizedCommunityExtAddress := "0:5d3e73af73f046cc75a9b6c5d82e63325ce79b6f080b39ec617e6c6183eb247b:"
		tokenizedCommunityCoins, _, _, err := a.fetchWalletInfoForCoins(ctx, "userID", []*CoinMapping{
			{
				Coin: &coins.Coin{
					ID:                                "tokenized-coin",
					Symbol:                            "updated-name",
					Network:                           "BscTestnet",
					ContractAddress:                   "0xbb88c364c759b2b42423b71f043212085d4cdeb0",
					Native:                            false,
					Name:                              "Tokenized Community Coin with non-matching symbol",
					TokenizedCommunityExternalAddress: &tokenizedCommunityExtAddress,
				},
				WalletID: &walletTokenizedCommunity,
				CoinID:   "tokenized-coin",
			},
		}, nil)
		require.NoError(t, err)
		require.NotEmpty(t, tokenizedCommunityCoins)
		require.Len(t, tokenizedCommunityCoins, 1)
		require.Contains(t, maps.Keys(tokenizedCommunityCoins), "0xbb88c364c759b2b42423b71f043212085d4cdeb0")
		require.EqualValues(t, "1113871018693693333332", tokenizedCommunityCoins["0xbb88c364c759b2b42423b71f043212085d4cdeb0"].TotalBalance.String())
		require.Len(t, tokenizedCommunityCoins["0xbb88c364c759b2b42423b71f043212085d4cdeb0"].Wallets, 1)
		require.Equal(t, []*CoinInWallet{
			{
				Asset:    &assetTokenizedCommunityCoin,
				WalletID: "wa-tokenized-community",
				Network:  "BscTestnet",
				CoinID:   "tokenized-coin",
			},
		}, tokenizedCommunityCoins["0xbb88c364c759b2b42423b71f043212085d4cdeb0"].Wallets)
	})
}

func (m *mockWalletClient) GetWalletHistory(ctx context.Context, walletID, paginationToken string, limit uint64) (*dfns.WalletHistory, error) {
	panic("not implemented")
}
func (m *mockWalletClient) GetWalletTransfers(ctx context.Context, walletID, paginationToken string, limit uint64) (*dfns.Transfers, error) {
	panic("not implemented")
}

func (m *mockIONIndexer) WalletTransactions(ctx context.Context, walletId, walletAddr, paginationToken string, limit uint64) ([]indexer.WalletHistoryItem, *string, error) {
	panic("not implemented")
}
