// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	stdlibtime "time"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/wintr/time"
)

type mockWalletClient struct {
	mockedWallets map[string]dfns.Wallet
}

type mockIONIndexer struct {
	indexerTriggered bool
}

func newMockedWalletClient() interface {
	dfns.DfnsClient
	Coins
} {
	wallets := map[string]dfns.Wallet{
		"wa-wallet1": map[string]any{
			"id":      "wa-wallet1",
			"network": "EthereumSepolia",
			"address": "addr1",
			"name":    "test wallet1",
			"signingKey": map[string]any{
				"publicKey": "e2375c8c9e87bfcd0be8f29d76c818cabacd51584f72cb2222d49a13b036d84d3d",
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
			"id":      "wa-wallet2",
			"network": "BscTestnet",
			"address": "addr2",
			"name":    "test wallet2",
			"signingKey": map[string]any{
				"publicKey": "e2375c8c9e87bfcd0be8f29d76c818cabacd51584f72cb2222d49a13b036d84d3d",
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
			"id":      "wa-wallet3",
			"network": "IonTestnet",
			"address": "addr3",
			"name":    "test wallet3",
			"signingKey": map[string]any{
				"publicKey": "masterKey",
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

func (m *mockWalletClient) VerifyWebhookSecret(fromWebhook string) bool {
	panic("TODO")
}

func (m *mockWalletClient) RegisterPostProxyCallback(url string, cb func(req *http.Request, now *time.Time, res map[string]any) error) {
	panic("TODO")
}

func (m *mockWalletClient) ListWallets(ctx context.Context, userID string) ([]dfns.Wallet, error) {
	res := []dfns.Wallet{}
	for _, w := range m.mockedWallets {
		delete(w, "assets")
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
func (m *mockWalletClient) ImportNFTs(ctx context.Context, network string, nft []coins.WalletNFT) ([]*coins.NFT, error) {
	res := []*coins.NFT{}
	for _, n := range nft {
		res = append(res, &coins.NFT{
			WalletNFT: n,
		})
	}
	return res, nil
}

func (m *mockIONIndexer) ListNFTs(ctx context.Context, walletAddr string, paginationToken string, limit uint) ([]coins.WalletNFT, *string, error) {
	m.indexerTriggered = true
	return []coins.WalletNFT{}, nil, nil
}

func TestFetchWalletInfoForCoinsAggregation(t *testing.T) {
	cl := newMockedWalletClient()
	ionIndexer := &mockIONIndexer{}
	a := &accounts{
		delegatedRPClient: cl,
		coinsRepo:         cl,
		ionNFT:            ionIndexer,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*stdlibtime.Second)
	defer cancel()
	wallet1, wallet2, wallet3 := "wa-wallet1", "wa-wallet2", "wa-wallet3"
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
				Symbol:          "ion",
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
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, nfts)
	require.NotEmpty(t, aggregatedCoins)
	require.Len(t, aggregatedCoins, 3)
	require.Contains(t, maps.Keys(aggregatedCoins), "usdc", "ice", "ion")
	assetUSDCOnBSC := dfns.Asset(map[string]any{
		"kind":     "Erc20",
		"contract": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
		"symbol":   "USDC",
		"decimals": 6,
		"verified": true,
		"balance":  "2000000",
	})
	assetUSDCOnSepolia := dfns.Asset(map[string]any{
		"kind":     "Erc20",
		"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"symbol":   "USDC",
		"decimals": 6,
		"verified": true,
		"balance":  "1000000",
	})
	require.EqualValues(t, &CoinAggregation{
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
	}, aggregatedCoins["usdc"])
	assetION := dfns.Asset(map[string]any{
		"kind":     "Native",
		"symbol":   "ice",
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

	require.True(t, ionIndexer.indexerTriggered)
}
