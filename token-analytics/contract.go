// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	_ "embed"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
)

type (
	TokenAnalytics interface {
		MustStart(ctx context.Context)
	}
)

var (
	//go:embed DDL.sql
	sourceDDL           string
	eventTokenCreated   = crypto.Keccak256Hash([]byte("BondedTokenCreated(address tokenAddress, string name, string symbol, uint256 totalSupply)"))
	eventPairRegistered = crypto.Keccak256Hash([]byte("PairRegistered(bytes32 pairId, address baseToken, address otherToken)"))
	eventSwapped        = crypto.Keccak256Hash([]byte("Swapped(address swapper, bytes32 pairId, bool direction, uint256 inputAmount, uint256 outputAmount, uint256 fee)"))
)

const (
	applicationYamlKey = "token-analytics"
)

type (
	config struct {
	}
	tokenAnalytics struct {
		ingestedDataDB  *storage.DB
		processedDataDB storagev3.DB
		shutdown        func() error
		cfg             *config
	}
)
