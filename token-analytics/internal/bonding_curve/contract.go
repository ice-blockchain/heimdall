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
		Address         common.Address
		Name            string
		Symbol          string
		ExternalAddress string
		TotalSupply     *big.Int
	}
	LogTokenSwapped struct {
		Event
		Address      common.Address
		Swapper      common.Address
		Pair         common.Hash
		Direction    bool
		TotalSupply  *big.Int
		InputAmount  *big.Int
		OutputAmount *big.Int
		Fee          *big.Int
		Params       map[string]any
	}
	LogRecipientsSet struct {
		Event
		PairId    common.Hash
		Creator   common.Address
		Affiliate common.Address
		Burn      common.Address
	}

	LogFeeAccrued struct {
		Event
		PairId      common.Hash
		Payer       common.Address
		Fee         *big.Int
		ToCreator   *big.Int
		ToAffiliate *big.Int
		ToBurn      *big.Int
	}

	LogFeeTransfer struct {
		Event
		PairId common.Hash
		To     common.Address
		Amount *big.Int
	}

	LogMigrated struct {
		Event
		PairId   common.Hash
		Pair     common.Address
		LpAmount *big.Int
	}

	LogLiquidityClaimed struct {
		Event
		PairId common.Hash
		To     common.Address
		Amount *big.Int
	}
	LogPairRegistered struct {
		Event
		PairId     common.Hash
		BaseToken  common.Address
		OtherToken common.Address
	}
	LogSlippageChecked struct {
		Event
		PairId    common.Hash
		MinReturn *big.Int
		ActualOut *big.Int
	}
	LogLiquidityLocked struct {
		Event
		PairId     common.Hash
		LpToken    common.Address
		Amount     *big.Int
		UnlockTime *big.Int
	}
	LogFeeWaived struct {
		Event
		PairId common.Hash
		User   common.Address
		Amount *big.Int
	}
	LogRefundIssued struct {
		Event
		PairId common.Hash
		User   common.Address
		Amount *big.Int
	}
	LogRouteSelected struct {
		Event
		PairId    common.Hash
		RouteType uint8
	}
	LogVerificationChecked struct {
		Event
		User     common.Address
		Verified bool
	}
)

var (
	ABI abi.ABI
	//go:embed .abi/bonding_curve.json
	ABIJSON string

	eventTokenCreated        = crypto.Keccak256Hash([]byte("BondingTokenCreated(address,string,string,string,uint256)"))
	eventPairRegistered      = crypto.Keccak256Hash([]byte("PairRegistered(bytes32,address,address)"))
	eventSwapped             = crypto.Keccak256Hash([]byte("Swapped(address,bytes32,bool,uint256,uint256,uint256)"))
	eventRecipientsSet       = crypto.Keccak256Hash([]byte("RecipientsSet(bytes32,address,address,address)"))
	eventFeeAccrued          = crypto.Keccak256Hash([]byte("FeeAccrued(bytes32,address,uint256,uint256,uint256,uint256)"))
	eventFeeTransfer         = crypto.Keccak256Hash([]byte("FeeTransfer(bytes32,address,uint256)"))
	eventFeeWaived           = crypto.Keccak256Hash([]byte("FeeWaived(bytes32,address,uint256)"))
	eventMigrated            = crypto.Keccak256Hash([]byte("Migrated(bytes32,address,uint256)"))
	eventLiquidityClaimed    = crypto.Keccak256Hash([]byte("LiquidityClaimed(bytes32,address,uint256)"))
	eventLiquidityLocked     = crypto.Keccak256Hash([]byte("LiquidityLocked(bytes32,address,uint256,uint256)"))
	eventSlippageChecked     = crypto.Keccak256Hash([]byte("SlippageChecked(bytes32,uint256,uint256)"))
	eventRefundIssued        = crypto.Keccak256Hash([]byte("RefundIssued(bytes32,address,uint256)"))
	eventRouteSelected       = crypto.Keccak256Hash([]byte("RouteSelected(bytes32,uint8)"))
	eventVerificationChecked = crypto.Keccak256Hash([]byte("VerificationChecked(address,bool)"))
)
