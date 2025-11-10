// SPDX-License-Identifier: ice License 1.0

package bondingcurve

import (
	_ "embed"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type (
	Event           interface{}
	LogTokenCreated struct {
		Event
		Address     common.Address
		Name        string
		Symbol      string
		TotalSupply *big.Int
	}
	LogTokenSwapped struct {
		Event
		Address      common.Address
		Pair         [32]byte
		Direction    bool
		TotalSupply  *big.Int
		InputAmount  *big.Int
		OutputAmount *big.Int
		Fee          *big.Int
	}
	LogTokenBought struct {
		Event
		Buyer    common.Address
		PairId   [32]byte
		AmountIn *big.Int
		TokenOut *big.Int
		Fee      *big.Int
	}

	LogTokenSold struct {
		Event
		Seller   common.Address
		PairId   [32]byte
		AmountIn *big.Int
		TokenOut *big.Int
		Fee      *big.Int
	}
	LogRecipientsSet struct {
		Event
		PairId    [32]byte
		Creator   common.Address
		Affiliate common.Address
		Burn      common.Address
	}

	LogFeeAccrued struct {
		Event
		PairId      [32]byte
		Payer       common.Address
		Fee         *big.Int
		ToCreator   *big.Int
		ToAffiliate *big.Int
		ToBurn      *big.Int
	}

	LogFeeTransfer struct {
		Event
		PairId [32]byte
		To     common.Address
		Amount *big.Int
	}

	LogMigrated struct {
		Event
		PairId   [32]byte
		Pair     common.Address
		LpAmount *big.Int
	}

	LogLPClaimed struct {
		Event
		PairId [32]byte
		To     common.Address
		Amount *big.Int
	}
	LogPairRegistered struct {
		Event
		PairId     [32]byte
		BaseToken  common.Address
		OtherToken common.Address
	}
)

var (
	bondingCurveABI abi.ABI
	//go:embed .abi/bonding_curve.json
	bondingCurveABIJSON string

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
