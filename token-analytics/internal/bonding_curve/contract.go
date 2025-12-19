// SPDX-License-Identifier: ice License 1.0

package bondingcurve

import (
	"context"
	_ "embed"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jellydator/ttlcache/v3"
	"golang.org/x/sync/singleflight"
)

type (
	Event           interface{}
	LogTokenCreated struct {
		Event
		Address          common.Address // indexed
		Name             string
		Symbol           string
		ExternalType     byte
		ExternalAddress  string
		TotalSupply      *big.Int
		CreatorAddress   common.Address
		AffiliateAddress common.Address
	}
	LogTokenSwapped struct {
		Event
		Swapper        common.Address
		Pair           common.Hash
		Direction      bool
		FeeToken       common.Address
		InputAmount    *big.Int
		OutputAmount   *big.Int
		Fee            *big.Int
		Params         map[string]any
		CustomHandleOp *CustomHandleOps
	}

	CustomUserOperation struct {
		Sender               common.Address `json:"sender"`
		Nonce                *big.Int       `json:"nonce"`
		InitCode             []byte         `json:"initCode"`
		CallData             []byte         `json:"callData"`
		CallGasLimit         *big.Int       `json:"callGasLimit"`
		VerificationGasLimit *big.Int       `json:"verificationGasLimit"`
		PreVerificationGas   *big.Int       `json:"preVerificationGas"`
		MaxFeePerGas         *big.Int       `json:"maxFeePerGas"`
		MaxPriorityFeePerGas *big.Int       `json:"maxPriorityFeePerGas"`
		PaymasterAndData     []byte         `json:"paymasterAndData"`
		Signature            []byte         `json:"signature"`
	}

	CustomHandleOps struct {
		Ops         []CustomUserOperation `json:"ops"`
		Beneficiary common.Address        `json:"beneficiary"`
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
		PairId                common.Hash
		Pool                  common.Address
		LockedLiquidityAmount *big.Int
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
		PriceModel common.Address
		StartPrice *big.Int
		EndPrice   *big.Int
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
	LogPoolCreated struct {
		Event
		Token0      common.Address // indexed
		Token1      common.Address //indexed
		Fee         *big.Int       // indexed
		TickSpacing *big.Int
		PoolAddress common.Address `abi:"pool"`
	}
	LogUniswapSwapped struct {
		Sender       common.Address
		Recipient    common.Address
		Amount0      *big.Int
		Amount1      *big.Int
		SqrtPriceX96 *big.Int
		Liquidity    *big.Int
		Tick         *big.Int
		PoolAddress  common.Address `abi:"-"`
	}
	BondingCurveProgress struct {
		*BondingCurveBondingInfo
		Liquidity *big.Int
	}
	BondingCurve interface {
		Pricing(ctx context.Context, baseToken common.Address, targetToken []byte, amount *big.Int, sale bool) (*big.Int, error)
		Progress(ctx context.Context, pairId common.Hash) (*BondingCurveProgress, error)
	}
)

var (
	ABI                abi.ABI
	UniswapABI         abi.ABI
	CustomHandleOpsABI abi.ABI
	//go:embed .abi/bonding_curve.json
	ABIJSON string
	//go:embed .abi/IUniswapV3Factory.json
	UniswapABIJSON string
	//go:embed .abi/CustomHandleOps.json
	CustomHandleOpsABIJSON string

	eventTokenCreated         = crypto.Keccak256Hash([]byte("BondingTokenCreated(address,string,string,uint8,string,uint256,address,address)"))
	eventPairRegistered       = crypto.Keccak256Hash([]byte("PairRegistered(bytes32,address,address,address,uint256,uint256)"))
	eventSwapped              = crypto.Keccak256Hash([]byte("Swapped(address,bytes32,bool,address,uint256,uint256,uint256)"))
	eventRecipientsSet        = crypto.Keccak256Hash([]byte("RecipientsSet(bytes32,address,address,address)"))
	eventFeeAccrued           = crypto.Keccak256Hash([]byte("FeeAccrued(bytes32,address,uint256,uint256,uint256,uint256)"))
	eventFeeTransfer          = crypto.Keccak256Hash([]byte("FeeTransfer(bytes32,address,uint256)"))
	eventFeeWaived            = crypto.Keccak256Hash([]byte("FeeWaived(bytes32,address,uint256)"))
	eventMigrated             = crypto.Keccak256Hash([]byte("Migrated(bytes32,address,uint256)"))
	eventLiquidityClaimed     = crypto.Keccak256Hash([]byte("LiquidityClaimed(bytes32,address,uint256)"))
	eventLiquidityLocked      = crypto.Keccak256Hash([]byte("LiquidityLocked(bytes32,address,uint256,uint256)"))
	eventSlippageChecked      = crypto.Keccak256Hash([]byte("SlippageChecked(bytes32,uint256,uint256)"))
	eventRefundIssued         = crypto.Keccak256Hash([]byte("RefundIssued(bytes32,address,uint256)"))
	eventRouteSelected        = crypto.Keccak256Hash([]byte("RouteSelected(bytes32,uint8)"))
	eventVerificationChecked  = crypto.Keccak256Hash([]byte("VerificationChecked(address,bool)"))
	eventPoolCreated          = crypto.Keccak256Hash([]byte("PoolCreated(address,address,uint24,int24,address)"))
	eventLiquidityMinted      = crypto.Keccak256Hash([]byte("Mint(address,address,int24,int24,uint128,uint256,uint256)"))
	eventLiquidityBurned      = crypto.Keccak256Hash([]byte("Burn(address,int24,int24,uint128,uint256,uint256)"))
	eventUniswapFeesCollected = crypto.Keccak256Hash([]byte("Collect(address,address,int24,int24,uint128,uint128)"))
	eventUniswapSwapped       = crypto.Keccak256Hash([]byte("Swap(address,address,int256,int256,uint160,uint128,int24)"))
)

type (
	bondingCurve struct {
		cfg                  config
		clientLBIndex        uint64
		rpcClients           []*ethclient.Client
		contractClients      []*BondingCurveTokenCaller
		pricingSingleflight  *singleflight.Group
		priceCache           *ttlcache.Cache[string, *big.Int]
		progressSingleflight *singleflight.Group
		progressCache        *ttlcache.Cache[string, *BondingCurveProgress]
	}
	config struct {
		BondingCurve struct {
			SmartContractAddress                string        `yaml:"smartContractAddress"`
			BondingCurveProgressUpdateFrequency time.Duration `yaml:"bondingCurveProgressUpdateFrequency"`
			RPCEndpoints                        []string      `yaml:"rpcEndpoints"`
		} `yaml:"bondingCurve" mapstructure:"bondingCurve"`
	}
)
