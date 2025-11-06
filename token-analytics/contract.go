// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	_ "embed"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/ice-blockchain/wintr/time"
)

type (
	TokenAnalytics interface {
		MustStart(ctx context.Context)
	}
)

var (
	//go:embed DDL.sql
	sourceDDL string
	//go:embed abi/BondingCurve.json
	bondedCurveABI      string
	eventTokenCreated   = crypto.Keccak256Hash([]byte("BondedTokenCreated(address,string,string,uint256)"))
	eventPairRegistered = crypto.Keccak256Hash([]byte("PairRegistered(bytes32 pairId, address baseToken, address otherToken)"))
	eventSwapped        = crypto.Keccak256Hash([]byte("Swapped(address,bytes32,bool,uint256,uint256,uint256)"))
	eventBought         = crypto.Keccak256Hash([]byte("Bought(address,bytes32,uint256,uint256,uint256)"))
	eventSold           = crypto.Keccak256Hash([]byte("Bought(address,bytes32,uint256,uint256,uint256)"))
	eventRecipientsSet  = crypto.Keccak256Hash([]byte("RecipientsSet(bytes32,address,address,address)"))
	eventFeeAccrued     = crypto.Keccak256Hash([]byte("FeeAccrued(bytes32, address,uint256,uint256,uint256,uint256)"))
	eventFeeTransfer    = crypto.Keccak256Hash([]byte("FeeTransfer(bytes32, address, uint256)"))
	eventMigrated       = crypto.Keccak256Hash([]byte("Migrated(bytes32,address,uint256)"))
	eventLPClaimed      = crypto.Keccak256Hash([]byte("LPClaimed(bytes32,address,uint256)"))
)

const (
	applicationYamlKey = "token-analytics"
)

type (
	config struct {
		Workers              uint   `yaml:"workers"`
		BatchSize            uint   `yaml:"batchSize"`
		BondingCurveContract string `yaml:"bondingCurveContract"`
	}
	tokenAnalytics struct {
		ingestedDataDB  *storage.DB
		processedDataDB storagev3.DB
		shutdown        func() error
		cfg             *config
		wg              *sync.WaitGroup
		bondingCurveABI abi.ABI
	}
	txEvent struct {
		*SavePoint
		IngestedAt      *time.Time `db:"ingested_at"`
		ProcessedAt     *time.Time `db:"processed_at"`
		TransactionHash string     `db:"transaction_hash"`
		Address         string     `db:"address"`
		FromAddress     string     `db:"from_address"`
		Data            string     `db:"data"`
		Topics          []string   `db:"topics"`
		Topic0          string     `db:"topic0"`
		StreamID        string     `db:"stream_id"`
		I               int        `db:"i"`
		Removed         bool       `db:"removed"`
	}

	SavePoint struct {
		TransactionIndex uint64 `db:"transaction_index"`
		BlockNumber      uint64 `db:"block_number"`
		LogIndex         uint64 `db:"log_index"`
	}

	logTokenCreated struct {
		Address     common.Address
		Name        string
		Symbol      string
		TotalSupply *big.Int
	}
	logTokenSwapped struct {
		Address      common.Address
		Pair         [32]byte
		Direction    bool
		TotalSupply  *big.Int
		InputAmount  *big.Int
		OutputAmount *big.Int
		Fee          *big.Int
	}
	logTokenBought struct {
		Buyer    common.Address
		PairId   [32]byte
		AmountIn *big.Int
		TokenOut *big.Int
		Fee      *big.Int
	}

	logTokenSold struct {
		Seller   common.Address
		PairId   [32]byte
		AmountIn *big.Int
		TokenOut *big.Int
		Fee      *big.Int
	}
	logRecipientsSet struct {
		PairId    [32]byte
		Creator   common.Address
		Affiliate common.Address
		Burn      common.Address
	}

	logFeeAccrued struct {
		PairId      [32]byte
		Payer       common.Address
		Fee         *big.Int
		ToCreator   *big.Int
		ToAffiliate *big.Int
		ToBurn      *big.Int
	}

	logFeeTransfer struct {
		PairId [32]byte
		To     common.Address
		Amount *big.Int
	}

	logMigrated struct {
		PairId   [32]byte
		Pair     common.Address
		LpAmount *big.Int
	}

	logLPClaimed struct {
		PairId [32]byte
		To     common.Address
		Amount *big.Int
	}
	logPairRegistered struct {
		PairId     [32]byte
		BaseToken  common.Address
		OtherToken common.Address
	}
)
