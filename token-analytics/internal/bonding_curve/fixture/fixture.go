// SPDX-License-Identifier: ice License 1.0

package fixture

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/stretchr/testify/require"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
)

type MockContractBackend struct {
	*simulated.Backend
	quoteBuyOutResponse     *big.Int
	quoteSellOutResponse    *big.Int
	bondingProgressResponse bondingcurve.BondingCurveBondingInfo
	balanceOfResponse       *big.Int
}

// Simulate deployed contract
func (m *MockContractBackend) CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error) {
	return []byte{0x60, 0x80, 0x60, 0x40, 0x52}, nil
}

func (m *MockContractBackend) PendingCodeAt(ctx context.Context, contract common.Address) ([]byte, error) {
	return []byte{0x60, 0x80, 0x60, 0x40, 0x52}, nil
}

func (m *MockContractBackend) CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	if len(call.Data) < 4 {
		return nil, errors.New("invalid call data")
	}

	methodID := [4]byte{call.Data[0], call.Data[1], call.Data[2], call.Data[3]}

	quoteBuyOutMethodID := [4]byte(crypto.Keccak256([]byte("quoteBuyOut(bytes,bytes,uint256)"))[:4])
	quoteSellOutMethodID := [4]byte(crypto.Keccak256([]byte("quoteSellOut(bytes,bytes,uint256)"))[:4])
	bondingProgressMethodID := [4]byte(crypto.Keccak256([]byte("bondingProgress(bytes32)"))[:4])
	balanceOfMethodID := [4]byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)

	if methodID == quoteBuyOutMethodID {
		return common.LeftPadBytes(m.quoteBuyOutResponse.Bytes(), 32), nil
	}

	if methodID == quoteSellOutMethodID {
		return common.LeftPadBytes(m.quoteSellOutResponse.Bytes(), 32), nil
	}

	if methodID == bondingProgressMethodID {
		encoded, _ := bondingcurve.ABI.Methods["bondingProgress"].Outputs.Pack(m.bondingProgressResponse)
		return encoded, nil
	}

	if methodID == balanceOfMethodID {
		if m.balanceOfResponse != nil {
			return common.LeftPadBytes(m.balanceOfResponse.Bytes(), 32), nil
		}
		return common.LeftPadBytes(big.NewInt(0).Bytes(), 32), nil
	}

	return m.Backend.Client().CallContract(ctx, call, blockNumber)
}

func (m *MockContractBackend) PendingCallContract(ctx context.Context, call ethereum.CallMsg) ([]byte, error) {
	return m.CallContract(ctx, call, nil)
}

type MockBackendConfig struct {
	// Pricing responses
	BuyPrice  *big.Int // Price for buying tokens (quoteBuyOut)
	SellPrice *big.Int // Price for selling tokens (quoteSellOut)

	// Bonding progress state
	SoldTokens        *big.Int
	TokensRaised      *big.Int
	StartPrice        *big.Int
	EndPrice          *big.Int
	BondingTokensGoal *big.Int
	CurrentPrice      *big.Int
	Migrated          bool
}

func DefaultMockBackendConfig() *MockBackendConfig {
	soldTokens, _ := new(big.Int).SetString("5000000000000000000000", 10)   // 5000 tokens
	tokensRaised, _ := new(big.Int).SetString("2500000000000000000000", 10) // 2500 tokens
	bondingGoal, _ := new(big.Int).SetString("10000000000000000000000", 10) // 10000 tokens

	return &MockBackendConfig{
		BuyPrice:          big.NewInt(950000000000000000),  // 0.95 tokens out for 1 token in
		SellPrice:         big.NewInt(1050000000000000000), // 1.05 tokens out for 1 token in
		SoldTokens:        soldTokens,
		TokensRaised:      tokensRaised,
		StartPrice:        big.NewInt(100000000000000000), // 0.1 start price
		EndPrice:          big.NewInt(200000000000000000), // 0.2 end price
		BondingTokensGoal: bondingGoal,
		CurrentPrice:      big.NewInt(150000000000000000), // 0.15 current price
		Migrated:          false,
	}
}

func SetupMockedBondingCurveBackend(t *testing.T, config *MockBackendConfig) (*MockContractBackend, common.Address, *bondingcurve.BondingCurveTokenCaller) {
	t.Helper()
	if config == nil {
		config = DefaultMockBackendConfig()
	}
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	auth, err := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))
	require.NoError(t, err)

	alloc := types.GenesisAlloc{
		auth.From: {
			Balance: new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)), // 1000 ETH
		},
	}
	sim := simulated.NewBackend(alloc)
	mock := &MockContractBackend{
		Backend:              sim,
		quoteBuyOutResponse:  config.BuyPrice,
		quoteSellOutResponse: config.SellPrice,
		bondingProgressResponse: bondingcurve.BondingCurveBondingInfo{
			SoldTokens:        config.SoldTokens,
			TokensRaised:      config.TokensRaised,
			StartPrice:        config.StartPrice,
			EndPrice:          config.EndPrice,
			BondingTokensGoal: config.BondingTokensGoal,
			CurrentPrice:      config.CurrentPrice,
			Migrated:          config.Migrated,
		},
	}

	contractAddress := common.HexToAddress("0x1234567890123456789012345678901234567890")
	caller, err := bondingcurve.NewBondingCurveTokenCaller(contractAddress, mock)
	require.NoError(t, err)

	return mock, contractAddress, caller
}

func CreateMockedBondingCurveInstance(caller *bondingcurve.BondingCurveTokenCaller, contractAddr common.Address) bondingcurve.BondingCurve {
	return &mockBondingCurveForTests{
		caller:   caller,
		contract: contractAddr,
	}
}

type mockBondingCurveForTests struct {
	caller   *bondingcurve.BondingCurveTokenCaller
	contract common.Address
}

func (m *mockBondingCurveForTests) Pricing(ctx context.Context, baseToken common.Address, targetToken []byte, amount *big.Int, sale bool) (*big.Int, error) {
	opts := &bind.CallOpts{Pending: true, Context: ctx}
	if sale {
		return m.caller.QuoteSellOut(opts, targetToken, baseToken.Bytes(), amount)
	}
	return m.caller.QuoteBuyOut(opts, baseToken.Bytes(), targetToken, amount)
}

func (m *mockBondingCurveForTests) Progress(ctx context.Context, pairId common.Hash) (*bondingcurve.BondingCurveProgress, error) {
	var pairIdBytes [32]byte
	copy(pairIdBytes[:], pairId.Bytes())
	opts := &bind.CallOpts{Pending: true, Context: ctx}
	info, err := m.caller.BondingProgress(opts, pairIdBytes)
	if err != nil {
		return nil, err
	}

	return &bondingcurve.BondingCurveProgress{
		BondingCurveBondingInfo: &info,
		Liquidity:               big.NewInt(0),
	}, nil
}

func (m *mockBondingCurveForTests) GetTokenBalance(ctx context.Context, tokenAddress common.Address, walletAddress common.Address) (*big.Int, error) {
	return big.NewInt(1000000000000000000), nil // 1 token (1e18 wei)
}

func (m *MockContractBackend) SetBalanceOfResponse(balance *big.Int) {
	m.balanceOfResponse = balance
}

func CreateMockedBondingCurveForBalanceTests(mock *MockContractBackend) bondingcurve.BondingCurve {
	return &mockBondingCurveWithRealBalance{
		mock: mock,
	}
}

type mockBondingCurveWithRealBalance struct {
	mock *MockContractBackend
}

func (m *mockBondingCurveWithRealBalance) Pricing(ctx context.Context, baseToken common.Address, targetToken []byte, amount *big.Int, sale bool) (*big.Int, error) {
	return big.NewInt(1000000000000000), nil
}

func (m *mockBondingCurveWithRealBalance) Progress(ctx context.Context, pairId common.Hash) (*bondingcurve.BondingCurveProgress, error) {
	return &bondingcurve.BondingCurveProgress{}, nil
}

func (m *mockBondingCurveWithRealBalance) GetTokenBalance(ctx context.Context, tokenAddress common.Address, walletAddress common.Address) (*big.Int, error) {
	data := make([]byte, 4+32)
	copy(data[0:4], []byte{0x70, 0xa0, 0x82, 0x31}) // balanceOf method ID
	copy(data[4:36], common.LeftPadBytes(walletAddress.Bytes(), 32))

	msg := ethereum.CallMsg{
		To:   &tokenAddress,
		Data: data,
	}

	result, err := m.mock.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return big.NewInt(0), nil
	}

	balance := new(big.Int).SetBytes(result)
	return balance, nil
}
