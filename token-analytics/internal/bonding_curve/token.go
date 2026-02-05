// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package bondingcurve

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// BondingCurveBondingInfo is an auto generated low-level Go binding around an user-defined struct.
type BondingCurveBondingInfo struct {
	SoldTokens        *big.Int
	TokensRaised      *big.Int
	StartPrice        *big.Int
	EndPrice          *big.Int
	BondingTokensGoal *big.Int
	CurrentPrice      *big.Int
	Migrated          bool
}

// BondingCurvePermitData is an auto generated low-level Go binding around an user-defined struct.
type BondingCurvePermitData struct {
	Value    *big.Int
	Deadline *big.Int
	V        uint8
	R        [32]byte
	S        [32]byte
}

// FeePolicyFeeBuckets is an auto generated low-level Go binding around an user-defined struct.
type FeePolicyFeeBuckets struct {
	CreatorAccrued   *big.Int
	AffiliateAccrued *big.Int
	BurnAccrued      *big.Int
}

// FeePolicyRecipients is an auto generated low-level Go binding around an user-defined struct.
type FeePolicyRecipients struct {
	Creator   common.Address
	Affiliate common.Address
	Burn      common.Address
}

// IUniswapV3MigratorHelperMigrationInfo is an auto generated low-level Go binding around an user-defined struct.
type IUniswapV3MigratorHelperMigrationInfo struct {
	Migrated              bool
	Pool                  common.Address
	LpToken               common.Address
	TokenId               *big.Int
	LockedLiquidityAmount *big.Int
}

// BondingCurveTokenMetaData contains all meta data concerning the BondingCurveToken contract.
var BondingCurveTokenMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"DoubleCreate\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InsufficientBaseLiquidity\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InsufficientFeeBalance\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvalidBps\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"invalidType\",\"type\":\"uint8\"}],\"name\":\"InvalidExternalType\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvalidFatAddressFormat\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvalidPool\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"invalidVersion\",\"type\":\"uint8\"}],\"name\":\"InvalidProtocolVersion\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvalidQuoter\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"invalidCount\",\"type\":\"uint8\"}],\"name\":\"InvalidRecordsCount\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"LiquidityLensNotSet\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"MigratorNotSet\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"NotCreator\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"PairDoesNotExist\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"minReturn\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"tokenOut\",\"type\":\"uint256\"}],\"name\":\"SlippageTooHigh\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"TokenNotMapped\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"UniswapQuoteFailed\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"UniswapRouterNotSet\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"UniswapTraderNotSet\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"ZeroAddress\",\"type\":\"error\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"payer\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"fee\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"toCreator\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"toAffiliate\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"toBurn\",\"type\":\"uint256\"}],\"name\":\"FeeAccrued\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"FeeTransfer\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"baseToken\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"otherToken\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"feeIsOtherToken\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"priceModel\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"startPrice\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"endPrice\",\"type\":\"uint256\"}],\"name\":\"PairRegistered\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"affiliate\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"burn\",\"type\":\"address\"}],\"name\":\"RecipientsSet\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"minReturn\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"actualOut\",\"type\":\"uint256\"}],\"name\":\"SlippageChecked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"swapper\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"direction\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"inputAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"outputAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"fee\",\"type\":\"uint256\"}],\"name\":\"Swapped\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"}],\"name\":\"bondingProgress\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"soldTokens\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"tokensRaised\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"startPrice\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"endPrice\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"bondingTokensGoal\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"currentPrice\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"migrated\",\"type\":\"bool\"}],\"internalType\":\"structBondingCurve.BondingInfo\",\"name\":\"info\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"}],\"name\":\"claimLockedLiquidity\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"compositeParamsToTokenAddress\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"config\",\"outputs\":[{\"internalType\":\"uint16\",\"name\":\"preMigrationFeeBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"postMigrationFeeBps\",\"type\":\"uint16\"},{\"internalType\":\"uint64\",\"name\":\"startTime\",\"type\":\"uint64\"},{\"internalType\":\"uint64\",\"name\":\"rampDuration\",\"type\":\"uint64\"},{\"internalType\":\"uint16\",\"name\":\"startCreatorBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"startAffiliateBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"startBurnBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"endCreatorBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"endAffiliateBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"endBurnBps\",\"type\":\"uint16\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_baseTokenAddress\",\"type\":\"address\"},{\"internalType\":\"string\",\"name\":\"_name\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"_symbol\",\"type\":\"string\"},{\"internalType\":\"uint8\",\"name\":\"_externalType\",\"type\":\"uint8\"},{\"internalType\":\"string\",\"name\":\"_externalAddress\",\"type\":\"string\"},{\"internalType\":\"address\",\"name\":\"_priceModel\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_startPrice\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_endPrice\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_totalSupply\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"_creatorAddress\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_affiliateAddress\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_burnAddress\",\"type\":\"address\"}],\"name\":\"createBondingToken\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"newTokenAddress\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"feePercentages\",\"outputs\":[{\"internalType\":\"uint16\",\"name\":\"cBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"aBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"bBps\",\"type\":\"uint16\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"}],\"name\":\"fees\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"creatorAccrued\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"affiliateAccrued\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"burnAccrued\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"}],\"name\":\"getAccrued\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"creatorAccrued\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"affiliateAccrued\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"burnAccrued\",\"type\":\"uint256\"}],\"internalType\":\"structFeePolicy.FeeBuckets\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"}],\"name\":\"getLiquidity\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"}],\"name\":\"getRecipients\",\"outputs\":[{\"components\":[{\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"affiliate\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"burn\",\"type\":\"address\"}],\"internalType\":\"structFeePolicy.Recipients\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint16\",\"name\":\"preMigrationFeeBps_\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"postMigrationFeeBps_\",\"type\":\"uint16\"},{\"internalType\":\"uint64\",\"name\":\"startTime_\",\"type\":\"uint64\"},{\"internalType\":\"address\",\"name\":\"uniswapV3Router_\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"uniswapV3Quoter_\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"uniswapV3MigratorHelper_\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"bondingTokenFactory_\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"defaultPriceModel_\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"uniswapTrader_\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"uncxLockAdapter_\",\"type\":\"address\"}],\"name\":\"initialize\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"}],\"name\":\"migrationOf\",\"outputs\":[{\"components\":[{\"internalType\":\"bool\",\"name\":\"migrated\",\"type\":\"bool\"},{\"internalType\":\"address\",\"name\":\"pool\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"lpToken\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"lockedLiquidityAmount\",\"type\":\"uint256\"}],\"internalType\":\"structIUniswapV3MigratorHelper.MigrationInfo\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"a\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"b\",\"type\":\"address\"}],\"name\":\"pairIdOf\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"pairs\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"baseTokenAddress\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"otherTokenAddress\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"feeIsOtherToken\",\"type\":\"bool\"},{\"internalType\":\"address\",\"name\":\"priceModel\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"uniswapPool\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"startPrice\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"endPrice\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"fromToken\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"toToken\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"amountInBase\",\"type\":\"uint256\"}],\"name\":\"quoteBuyOut\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"amountOutOther\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"fromToken\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"toToken\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"amountInOther\",\"type\":\"uint256\"}],\"name\":\"quoteSellOut\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"amountOutBase\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"fromToken\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"toToken\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"amountIn\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"minReturn\",\"type\":\"uint256\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"deadline\",\"type\":\"uint256\"},{\"internalType\":\"uint8\",\"name\":\"v\",\"type\":\"uint8\"},{\"internalType\":\"bytes32\",\"name\":\"r\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"s\",\"type\":\"bytes32\"}],\"internalType\":\"structBondingCurve.PermitData\",\"name\":\"permit\",\"type\":\"tuple\"}],\"name\":\"swap\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"fromToken\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"toToken\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"amountIn\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"minReturn\",\"type\":\"uint256\"}],\"name\":\"swap\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
}

// BondingCurveTokenABI is the input ABI used to generate the binding from.
// Deprecated: Use BondingCurveTokenMetaData.ABI instead.
var BondingCurveTokenABI = BondingCurveTokenMetaData.ABI

// BondingCurveToken is an auto generated Go binding around an Ethereum contract.
type BondingCurveToken struct {
	BondingCurveTokenCaller     // Read-only binding to the contract
	BondingCurveTokenTransactor // Write-only binding to the contract
	BondingCurveTokenFilterer   // Log filterer for contract events
}

// BondingCurveTokenCaller is an auto generated read-only Go binding around an Ethereum contract.
type BondingCurveTokenCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// BondingCurveTokenTransactor is an auto generated write-only Go binding around an Ethereum contract.
type BondingCurveTokenTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// BondingCurveTokenFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type BondingCurveTokenFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// BondingCurveTokenSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type BondingCurveTokenSession struct {
	Contract     *BondingCurveToken // Generic contract binding to set the session for
	CallOpts     bind.CallOpts      // Call options to use throughout this session
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// BondingCurveTokenCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type BondingCurveTokenCallerSession struct {
	Contract *BondingCurveTokenCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts            // Call options to use throughout this session
}

// BondingCurveTokenTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type BondingCurveTokenTransactorSession struct {
	Contract     *BondingCurveTokenTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts            // Transaction auth options to use throughout this session
}

// BondingCurveTokenRaw is an auto generated low-level Go binding around an Ethereum contract.
type BondingCurveTokenRaw struct {
	Contract *BondingCurveToken // Generic contract binding to access the raw methods on
}

// BondingCurveTokenCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type BondingCurveTokenCallerRaw struct {
	Contract *BondingCurveTokenCaller // Generic read-only contract binding to access the raw methods on
}

// BondingCurveTokenTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type BondingCurveTokenTransactorRaw struct {
	Contract *BondingCurveTokenTransactor // Generic write-only contract binding to access the raw methods on
}

// NewBondingCurveToken creates a new instance of BondingCurveToken, bound to a specific deployed contract.
func NewBondingCurveToken(address common.Address, backend bind.ContractBackend) (*BondingCurveToken, error) {
	contract, err := bindBondingCurveToken(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &BondingCurveToken{BondingCurveTokenCaller: BondingCurveTokenCaller{contract: contract}, BondingCurveTokenTransactor: BondingCurveTokenTransactor{contract: contract}, BondingCurveTokenFilterer: BondingCurveTokenFilterer{contract: contract}}, nil
}

// NewBondingCurveTokenCaller creates a new read-only instance of BondingCurveToken, bound to a specific deployed contract.
func NewBondingCurveTokenCaller(address common.Address, caller bind.ContractCaller) (*BondingCurveTokenCaller, error) {
	contract, err := bindBondingCurveToken(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenCaller{contract: contract}, nil
}

// NewBondingCurveTokenTransactor creates a new write-only instance of BondingCurveToken, bound to a specific deployed contract.
func NewBondingCurveTokenTransactor(address common.Address, transactor bind.ContractTransactor) (*BondingCurveTokenTransactor, error) {
	contract, err := bindBondingCurveToken(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenTransactor{contract: contract}, nil
}

// NewBondingCurveTokenFilterer creates a new log filterer instance of BondingCurveToken, bound to a specific deployed contract.
func NewBondingCurveTokenFilterer(address common.Address, filterer bind.ContractFilterer) (*BondingCurveTokenFilterer, error) {
	contract, err := bindBondingCurveToken(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenFilterer{contract: contract}, nil
}

// bindBondingCurveToken binds a generic wrapper to an already deployed contract.
func bindBondingCurveToken(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := BondingCurveTokenMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_BondingCurveToken *BondingCurveTokenRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _BondingCurveToken.Contract.BondingCurveTokenCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_BondingCurveToken *BondingCurveTokenRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.BondingCurveTokenTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_BondingCurveToken *BondingCurveTokenRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.BondingCurveTokenTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_BondingCurveToken *BondingCurveTokenCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _BondingCurveToken.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_BondingCurveToken *BondingCurveTokenTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_BondingCurveToken *BondingCurveTokenTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.contract.Transact(opts, method, params...)
}

// BondingProgress is a free data retrieval call binding the contract method 0x1c216a98.
//
// Solidity: function bondingProgress(bytes32 pairId) view returns((uint256,uint256,uint256,uint256,uint256,uint256,bool) info)
func (_BondingCurveToken *BondingCurveTokenCaller) BondingProgress(opts *bind.CallOpts, pairId [32]byte) (BondingCurveBondingInfo, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "bondingProgress", pairId)

	if err != nil {
		return *new(BondingCurveBondingInfo), err
	}

	out0 := *abi.ConvertType(out[0], new(BondingCurveBondingInfo)).(*BondingCurveBondingInfo)

	return out0, err

}

// BondingProgress is a free data retrieval call binding the contract method 0x1c216a98.
//
// Solidity: function bondingProgress(bytes32 pairId) view returns((uint256,uint256,uint256,uint256,uint256,uint256,bool) info)
func (_BondingCurveToken *BondingCurveTokenSession) BondingProgress(pairId [32]byte) (BondingCurveBondingInfo, error) {
	return _BondingCurveToken.Contract.BondingProgress(&_BondingCurveToken.CallOpts, pairId)
}

// BondingProgress is a free data retrieval call binding the contract method 0x1c216a98.
//
// Solidity: function bondingProgress(bytes32 pairId) view returns((uint256,uint256,uint256,uint256,uint256,uint256,bool) info)
func (_BondingCurveToken *BondingCurveTokenCallerSession) BondingProgress(pairId [32]byte) (BondingCurveBondingInfo, error) {
	return _BondingCurveToken.Contract.BondingProgress(&_BondingCurveToken.CallOpts, pairId)
}

// CompositeParamsToTokenAddress is a free data retrieval call binding the contract method 0x24ecbfc8.
//
// Solidity: function compositeParamsToTokenAddress(bytes32 ) view returns(address)
func (_BondingCurveToken *BondingCurveTokenCaller) CompositeParamsToTokenAddress(opts *bind.CallOpts, arg0 [32]byte) (common.Address, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "compositeParamsToTokenAddress", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// CompositeParamsToTokenAddress is a free data retrieval call binding the contract method 0x24ecbfc8.
//
// Solidity: function compositeParamsToTokenAddress(bytes32 ) view returns(address)
func (_BondingCurveToken *BondingCurveTokenSession) CompositeParamsToTokenAddress(arg0 [32]byte) (common.Address, error) {
	return _BondingCurveToken.Contract.CompositeParamsToTokenAddress(&_BondingCurveToken.CallOpts, arg0)
}

// CompositeParamsToTokenAddress is a free data retrieval call binding the contract method 0x24ecbfc8.
//
// Solidity: function compositeParamsToTokenAddress(bytes32 ) view returns(address)
func (_BondingCurveToken *BondingCurveTokenCallerSession) CompositeParamsToTokenAddress(arg0 [32]byte) (common.Address, error) {
	return _BondingCurveToken.Contract.CompositeParamsToTokenAddress(&_BondingCurveToken.CallOpts, arg0)
}

// Config is a free data retrieval call binding the contract method 0x79502c55.
//
// Solidity: function config() view returns(uint16 preMigrationFeeBps, uint16 postMigrationFeeBps, uint64 startTime, uint64 rampDuration, uint16 startCreatorBps, uint16 startAffiliateBps, uint16 startBurnBps, uint16 endCreatorBps, uint16 endAffiliateBps, uint16 endBurnBps)
func (_BondingCurveToken *BondingCurveTokenCaller) Config(opts *bind.CallOpts) (struct {
	PreMigrationFeeBps  uint16
	PostMigrationFeeBps uint16
	StartTime           uint64
	RampDuration        uint64
	StartCreatorBps     uint16
	StartAffiliateBps   uint16
	StartBurnBps        uint16
	EndCreatorBps       uint16
	EndAffiliateBps     uint16
	EndBurnBps          uint16
}, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "config")

	outstruct := new(struct {
		PreMigrationFeeBps  uint16
		PostMigrationFeeBps uint16
		StartTime           uint64
		RampDuration        uint64
		StartCreatorBps     uint16
		StartAffiliateBps   uint16
		StartBurnBps        uint16
		EndCreatorBps       uint16
		EndAffiliateBps     uint16
		EndBurnBps          uint16
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.PreMigrationFeeBps = *abi.ConvertType(out[0], new(uint16)).(*uint16)
	outstruct.PostMigrationFeeBps = *abi.ConvertType(out[1], new(uint16)).(*uint16)
	outstruct.StartTime = *abi.ConvertType(out[2], new(uint64)).(*uint64)
	outstruct.RampDuration = *abi.ConvertType(out[3], new(uint64)).(*uint64)
	outstruct.StartCreatorBps = *abi.ConvertType(out[4], new(uint16)).(*uint16)
	outstruct.StartAffiliateBps = *abi.ConvertType(out[5], new(uint16)).(*uint16)
	outstruct.StartBurnBps = *abi.ConvertType(out[6], new(uint16)).(*uint16)
	outstruct.EndCreatorBps = *abi.ConvertType(out[7], new(uint16)).(*uint16)
	outstruct.EndAffiliateBps = *abi.ConvertType(out[8], new(uint16)).(*uint16)
	outstruct.EndBurnBps = *abi.ConvertType(out[9], new(uint16)).(*uint16)

	return *outstruct, err

}

// Config is a free data retrieval call binding the contract method 0x79502c55.
//
// Solidity: function config() view returns(uint16 preMigrationFeeBps, uint16 postMigrationFeeBps, uint64 startTime, uint64 rampDuration, uint16 startCreatorBps, uint16 startAffiliateBps, uint16 startBurnBps, uint16 endCreatorBps, uint16 endAffiliateBps, uint16 endBurnBps)
func (_BondingCurveToken *BondingCurveTokenSession) Config() (struct {
	PreMigrationFeeBps  uint16
	PostMigrationFeeBps uint16
	StartTime           uint64
	RampDuration        uint64
	StartCreatorBps     uint16
	StartAffiliateBps   uint16
	StartBurnBps        uint16
	EndCreatorBps       uint16
	EndAffiliateBps     uint16
	EndBurnBps          uint16
}, error) {
	return _BondingCurveToken.Contract.Config(&_BondingCurveToken.CallOpts)
}

// Config is a free data retrieval call binding the contract method 0x79502c55.
//
// Solidity: function config() view returns(uint16 preMigrationFeeBps, uint16 postMigrationFeeBps, uint64 startTime, uint64 rampDuration, uint16 startCreatorBps, uint16 startAffiliateBps, uint16 startBurnBps, uint16 endCreatorBps, uint16 endAffiliateBps, uint16 endBurnBps)
func (_BondingCurveToken *BondingCurveTokenCallerSession) Config() (struct {
	PreMigrationFeeBps  uint16
	PostMigrationFeeBps uint16
	StartTime           uint64
	RampDuration        uint64
	StartCreatorBps     uint16
	StartAffiliateBps   uint16
	StartBurnBps        uint16
	EndCreatorBps       uint16
	EndAffiliateBps     uint16
	EndBurnBps          uint16
}, error) {
	return _BondingCurveToken.Contract.Config(&_BondingCurveToken.CallOpts)
}

// FeePercentages is a free data retrieval call binding the contract method 0xa0e9bf34.
//
// Solidity: function feePercentages() view returns(uint16 cBps, uint16 aBps, uint16 bBps)
func (_BondingCurveToken *BondingCurveTokenCaller) FeePercentages(opts *bind.CallOpts) (struct {
	CBps uint16
	ABps uint16
	BBps uint16
}, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "feePercentages")

	outstruct := new(struct {
		CBps uint16
		ABps uint16
		BBps uint16
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.CBps = *abi.ConvertType(out[0], new(uint16)).(*uint16)
	outstruct.ABps = *abi.ConvertType(out[1], new(uint16)).(*uint16)
	outstruct.BBps = *abi.ConvertType(out[2], new(uint16)).(*uint16)

	return *outstruct, err

}

// FeePercentages is a free data retrieval call binding the contract method 0xa0e9bf34.
//
// Solidity: function feePercentages() view returns(uint16 cBps, uint16 aBps, uint16 bBps)
func (_BondingCurveToken *BondingCurveTokenSession) FeePercentages() (struct {
	CBps uint16
	ABps uint16
	BBps uint16
}, error) {
	return _BondingCurveToken.Contract.FeePercentages(&_BondingCurveToken.CallOpts)
}

// FeePercentages is a free data retrieval call binding the contract method 0xa0e9bf34.
//
// Solidity: function feePercentages() view returns(uint16 cBps, uint16 aBps, uint16 bBps)
func (_BondingCurveToken *BondingCurveTokenCallerSession) FeePercentages() (struct {
	CBps uint16
	ABps uint16
	BBps uint16
}, error) {
	return _BondingCurveToken.Contract.FeePercentages(&_BondingCurveToken.CallOpts)
}

// Fees is a free data retrieval call binding the contract method 0xcdb5661f.
//
// Solidity: function fees(bytes32 pairId) view returns(uint256 creatorAccrued, uint256 affiliateAccrued, uint256 burnAccrued)
func (_BondingCurveToken *BondingCurveTokenCaller) Fees(opts *bind.CallOpts, pairId [32]byte) (struct {
	CreatorAccrued   *big.Int
	AffiliateAccrued *big.Int
	BurnAccrued      *big.Int
}, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "fees", pairId)

	outstruct := new(struct {
		CreatorAccrued   *big.Int
		AffiliateAccrued *big.Int
		BurnAccrued      *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.CreatorAccrued = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.AffiliateAccrued = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.BurnAccrued = *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// Fees is a free data retrieval call binding the contract method 0xcdb5661f.
//
// Solidity: function fees(bytes32 pairId) view returns(uint256 creatorAccrued, uint256 affiliateAccrued, uint256 burnAccrued)
func (_BondingCurveToken *BondingCurveTokenSession) Fees(pairId [32]byte) (struct {
	CreatorAccrued   *big.Int
	AffiliateAccrued *big.Int
	BurnAccrued      *big.Int
}, error) {
	return _BondingCurveToken.Contract.Fees(&_BondingCurveToken.CallOpts, pairId)
}

// Fees is a free data retrieval call binding the contract method 0xcdb5661f.
//
// Solidity: function fees(bytes32 pairId) view returns(uint256 creatorAccrued, uint256 affiliateAccrued, uint256 burnAccrued)
func (_BondingCurveToken *BondingCurveTokenCallerSession) Fees(pairId [32]byte) (struct {
	CreatorAccrued   *big.Int
	AffiliateAccrued *big.Int
	BurnAccrued      *big.Int
}, error) {
	return _BondingCurveToken.Contract.Fees(&_BondingCurveToken.CallOpts, pairId)
}

// GetAccrued is a free data retrieval call binding the contract method 0xdb895bb0.
//
// Solidity: function getAccrued(bytes32 pairId) view returns((uint256,uint256,uint256))
func (_BondingCurveToken *BondingCurveTokenCaller) GetAccrued(opts *bind.CallOpts, pairId [32]byte) (FeePolicyFeeBuckets, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "getAccrued", pairId)

	if err != nil {
		return *new(FeePolicyFeeBuckets), err
	}

	out0 := *abi.ConvertType(out[0], new(FeePolicyFeeBuckets)).(*FeePolicyFeeBuckets)

	return out0, err

}

// GetAccrued is a free data retrieval call binding the contract method 0xdb895bb0.
//
// Solidity: function getAccrued(bytes32 pairId) view returns((uint256,uint256,uint256))
func (_BondingCurveToken *BondingCurveTokenSession) GetAccrued(pairId [32]byte) (FeePolicyFeeBuckets, error) {
	return _BondingCurveToken.Contract.GetAccrued(&_BondingCurveToken.CallOpts, pairId)
}

// GetAccrued is a free data retrieval call binding the contract method 0xdb895bb0.
//
// Solidity: function getAccrued(bytes32 pairId) view returns((uint256,uint256,uint256))
func (_BondingCurveToken *BondingCurveTokenCallerSession) GetAccrued(pairId [32]byte) (FeePolicyFeeBuckets, error) {
	return _BondingCurveToken.Contract.GetAccrued(&_BondingCurveToken.CallOpts, pairId)
}

// GetLiquidity is a free data retrieval call binding the contract method 0xfa6793d5.
//
// Solidity: function getLiquidity(bytes32 pairId) view returns(uint256)
func (_BondingCurveToken *BondingCurveTokenCaller) GetLiquidity(opts *bind.CallOpts, pairId [32]byte) (*big.Int, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "getLiquidity", pairId)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetLiquidity is a free data retrieval call binding the contract method 0xfa6793d5.
//
// Solidity: function getLiquidity(bytes32 pairId) view returns(uint256)
func (_BondingCurveToken *BondingCurveTokenSession) GetLiquidity(pairId [32]byte) (*big.Int, error) {
	return _BondingCurveToken.Contract.GetLiquidity(&_BondingCurveToken.CallOpts, pairId)
}

// GetLiquidity is a free data retrieval call binding the contract method 0xfa6793d5.
//
// Solidity: function getLiquidity(bytes32 pairId) view returns(uint256)
func (_BondingCurveToken *BondingCurveTokenCallerSession) GetLiquidity(pairId [32]byte) (*big.Int, error) {
	return _BondingCurveToken.Contract.GetLiquidity(&_BondingCurveToken.CallOpts, pairId)
}

// GetRecipients is a free data retrieval call binding the contract method 0x9aac9494.
//
// Solidity: function getRecipients(bytes32 pairId) view returns((address,address,address))
func (_BondingCurveToken *BondingCurveTokenCaller) GetRecipients(opts *bind.CallOpts, pairId [32]byte) (FeePolicyRecipients, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "getRecipients", pairId)

	if err != nil {
		return *new(FeePolicyRecipients), err
	}

	out0 := *abi.ConvertType(out[0], new(FeePolicyRecipients)).(*FeePolicyRecipients)

	return out0, err

}

// GetRecipients is a free data retrieval call binding the contract method 0x9aac9494.
//
// Solidity: function getRecipients(bytes32 pairId) view returns((address,address,address))
func (_BondingCurveToken *BondingCurveTokenSession) GetRecipients(pairId [32]byte) (FeePolicyRecipients, error) {
	return _BondingCurveToken.Contract.GetRecipients(&_BondingCurveToken.CallOpts, pairId)
}

// GetRecipients is a free data retrieval call binding the contract method 0x9aac9494.
//
// Solidity: function getRecipients(bytes32 pairId) view returns((address,address,address))
func (_BondingCurveToken *BondingCurveTokenCallerSession) GetRecipients(pairId [32]byte) (FeePolicyRecipients, error) {
	return _BondingCurveToken.Contract.GetRecipients(&_BondingCurveToken.CallOpts, pairId)
}

// MigrationOf is a free data retrieval call binding the contract method 0x2fa9c64e.
//
// Solidity: function migrationOf(bytes32 pairId) view returns((bool,address,address,uint256,uint256))
func (_BondingCurveToken *BondingCurveTokenCaller) MigrationOf(opts *bind.CallOpts, pairId [32]byte) (IUniswapV3MigratorHelperMigrationInfo, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "migrationOf", pairId)

	if err != nil {
		return *new(IUniswapV3MigratorHelperMigrationInfo), err
	}

	out0 := *abi.ConvertType(out[0], new(IUniswapV3MigratorHelperMigrationInfo)).(*IUniswapV3MigratorHelperMigrationInfo)

	return out0, err

}

// MigrationOf is a free data retrieval call binding the contract method 0x2fa9c64e.
//
// Solidity: function migrationOf(bytes32 pairId) view returns((bool,address,address,uint256,uint256))
func (_BondingCurveToken *BondingCurveTokenSession) MigrationOf(pairId [32]byte) (IUniswapV3MigratorHelperMigrationInfo, error) {
	return _BondingCurveToken.Contract.MigrationOf(&_BondingCurveToken.CallOpts, pairId)
}

// MigrationOf is a free data retrieval call binding the contract method 0x2fa9c64e.
//
// Solidity: function migrationOf(bytes32 pairId) view returns((bool,address,address,uint256,uint256))
func (_BondingCurveToken *BondingCurveTokenCallerSession) MigrationOf(pairId [32]byte) (IUniswapV3MigratorHelperMigrationInfo, error) {
	return _BondingCurveToken.Contract.MigrationOf(&_BondingCurveToken.CallOpts, pairId)
}

// PairIdOf is a free data retrieval call binding the contract method 0xa8efeb69.
//
// Solidity: function pairIdOf(address a, address b) pure returns(bytes32)
func (_BondingCurveToken *BondingCurveTokenCaller) PairIdOf(opts *bind.CallOpts, a common.Address, b common.Address) ([32]byte, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "pairIdOf", a, b)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// PairIdOf is a free data retrieval call binding the contract method 0xa8efeb69.
//
// Solidity: function pairIdOf(address a, address b) pure returns(bytes32)
func (_BondingCurveToken *BondingCurveTokenSession) PairIdOf(a common.Address, b common.Address) ([32]byte, error) {
	return _BondingCurveToken.Contract.PairIdOf(&_BondingCurveToken.CallOpts, a, b)
}

// PairIdOf is a free data retrieval call binding the contract method 0xa8efeb69.
//
// Solidity: function pairIdOf(address a, address b) pure returns(bytes32)
func (_BondingCurveToken *BondingCurveTokenCallerSession) PairIdOf(a common.Address, b common.Address) ([32]byte, error) {
	return _BondingCurveToken.Contract.PairIdOf(&_BondingCurveToken.CallOpts, a, b)
}

// Pairs is a free data retrieval call binding the contract method 0x673e0481.
//
// Solidity: function pairs(bytes32 ) view returns(address baseTokenAddress, address otherTokenAddress, address creator, bool feeIsOtherToken, address priceModel, address uniswapPool, uint256 startPrice, uint256 endPrice)
func (_BondingCurveToken *BondingCurveTokenCaller) Pairs(opts *bind.CallOpts, arg0 [32]byte) (struct {
	BaseTokenAddress  common.Address
	OtherTokenAddress common.Address
	Creator           common.Address
	FeeIsOtherToken   bool
	PriceModel        common.Address
	UniswapPool       common.Address
	StartPrice        *big.Int
	EndPrice          *big.Int
}, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "pairs", arg0)

	outstruct := new(struct {
		BaseTokenAddress  common.Address
		OtherTokenAddress common.Address
		Creator           common.Address
		FeeIsOtherToken   bool
		PriceModel        common.Address
		UniswapPool       common.Address
		StartPrice        *big.Int
		EndPrice          *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.BaseTokenAddress = *abi.ConvertType(out[0], new(common.Address)).(*common.Address)
	outstruct.OtherTokenAddress = *abi.ConvertType(out[1], new(common.Address)).(*common.Address)
	outstruct.Creator = *abi.ConvertType(out[2], new(common.Address)).(*common.Address)
	outstruct.FeeIsOtherToken = *abi.ConvertType(out[3], new(bool)).(*bool)
	outstruct.PriceModel = *abi.ConvertType(out[4], new(common.Address)).(*common.Address)
	outstruct.UniswapPool = *abi.ConvertType(out[5], new(common.Address)).(*common.Address)
	outstruct.StartPrice = *abi.ConvertType(out[6], new(*big.Int)).(**big.Int)
	outstruct.EndPrice = *abi.ConvertType(out[7], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// Pairs is a free data retrieval call binding the contract method 0x673e0481.
//
// Solidity: function pairs(bytes32 ) view returns(address baseTokenAddress, address otherTokenAddress, address creator, bool feeIsOtherToken, address priceModel, address uniswapPool, uint256 startPrice, uint256 endPrice)
func (_BondingCurveToken *BondingCurveTokenSession) Pairs(arg0 [32]byte) (struct {
	BaseTokenAddress  common.Address
	OtherTokenAddress common.Address
	Creator           common.Address
	FeeIsOtherToken   bool
	PriceModel        common.Address
	UniswapPool       common.Address
	StartPrice        *big.Int
	EndPrice          *big.Int
}, error) {
	return _BondingCurveToken.Contract.Pairs(&_BondingCurveToken.CallOpts, arg0)
}

// Pairs is a free data retrieval call binding the contract method 0x673e0481.
//
// Solidity: function pairs(bytes32 ) view returns(address baseTokenAddress, address otherTokenAddress, address creator, bool feeIsOtherToken, address priceModel, address uniswapPool, uint256 startPrice, uint256 endPrice)
func (_BondingCurveToken *BondingCurveTokenCallerSession) Pairs(arg0 [32]byte) (struct {
	BaseTokenAddress  common.Address
	OtherTokenAddress common.Address
	Creator           common.Address
	FeeIsOtherToken   bool
	PriceModel        common.Address
	UniswapPool       common.Address
	StartPrice        *big.Int
	EndPrice          *big.Int
}, error) {
	return _BondingCurveToken.Contract.Pairs(&_BondingCurveToken.CallOpts, arg0)
}

// QuoteBuyOut is a free data retrieval call binding the contract method 0x5413a6d4.
//
// Solidity: function quoteBuyOut(bytes fromToken, bytes toToken, uint256 amountInBase) view returns(uint256 amountOutOther)
func (_BondingCurveToken *BondingCurveTokenCaller) QuoteBuyOut(opts *bind.CallOpts, fromToken []byte, toToken []byte, amountInBase *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "quoteBuyOut", fromToken, toToken, amountInBase)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// QuoteBuyOut is a free data retrieval call binding the contract method 0x5413a6d4.
//
// Solidity: function quoteBuyOut(bytes fromToken, bytes toToken, uint256 amountInBase) view returns(uint256 amountOutOther)
func (_BondingCurveToken *BondingCurveTokenSession) QuoteBuyOut(fromToken []byte, toToken []byte, amountInBase *big.Int) (*big.Int, error) {
	return _BondingCurveToken.Contract.QuoteBuyOut(&_BondingCurveToken.CallOpts, fromToken, toToken, amountInBase)
}

// QuoteBuyOut is a free data retrieval call binding the contract method 0x5413a6d4.
//
// Solidity: function quoteBuyOut(bytes fromToken, bytes toToken, uint256 amountInBase) view returns(uint256 amountOutOther)
func (_BondingCurveToken *BondingCurveTokenCallerSession) QuoteBuyOut(fromToken []byte, toToken []byte, amountInBase *big.Int) (*big.Int, error) {
	return _BondingCurveToken.Contract.QuoteBuyOut(&_BondingCurveToken.CallOpts, fromToken, toToken, amountInBase)
}

// QuoteSellOut is a free data retrieval call binding the contract method 0x1c22fee2.
//
// Solidity: function quoteSellOut(bytes fromToken, bytes toToken, uint256 amountInOther) view returns(uint256 amountOutBase)
func (_BondingCurveToken *BondingCurveTokenCaller) QuoteSellOut(opts *bind.CallOpts, fromToken []byte, toToken []byte, amountInOther *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "quoteSellOut", fromToken, toToken, amountInOther)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// QuoteSellOut is a free data retrieval call binding the contract method 0x1c22fee2.
//
// Solidity: function quoteSellOut(bytes fromToken, bytes toToken, uint256 amountInOther) view returns(uint256 amountOutBase)
func (_BondingCurveToken *BondingCurveTokenSession) QuoteSellOut(fromToken []byte, toToken []byte, amountInOther *big.Int) (*big.Int, error) {
	return _BondingCurveToken.Contract.QuoteSellOut(&_BondingCurveToken.CallOpts, fromToken, toToken, amountInOther)
}

// QuoteSellOut is a free data retrieval call binding the contract method 0x1c22fee2.
//
// Solidity: function quoteSellOut(bytes fromToken, bytes toToken, uint256 amountInOther) view returns(uint256 amountOutBase)
func (_BondingCurveToken *BondingCurveTokenCallerSession) QuoteSellOut(fromToken []byte, toToken []byte, amountInOther *big.Int) (*big.Int, error) {
	return _BondingCurveToken.Contract.QuoteSellOut(&_BondingCurveToken.CallOpts, fromToken, toToken, amountInOther)
}

// ClaimLockedLiquidity is a paid mutator transaction binding the contract method 0x7761f58a.
//
// Solidity: function claimLockedLiquidity(bytes32 pairId, address to) returns(uint256 amount)
func (_BondingCurveToken *BondingCurveTokenTransactor) ClaimLockedLiquidity(opts *bind.TransactOpts, pairId [32]byte, to common.Address) (*types.Transaction, error) {
	return _BondingCurveToken.contract.Transact(opts, "claimLockedLiquidity", pairId, to)
}

// ClaimLockedLiquidity is a paid mutator transaction binding the contract method 0x7761f58a.
//
// Solidity: function claimLockedLiquidity(bytes32 pairId, address to) returns(uint256 amount)
func (_BondingCurveToken *BondingCurveTokenSession) ClaimLockedLiquidity(pairId [32]byte, to common.Address) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.ClaimLockedLiquidity(&_BondingCurveToken.TransactOpts, pairId, to)
}

// ClaimLockedLiquidity is a paid mutator transaction binding the contract method 0x7761f58a.
//
// Solidity: function claimLockedLiquidity(bytes32 pairId, address to) returns(uint256 amount)
func (_BondingCurveToken *BondingCurveTokenTransactorSession) ClaimLockedLiquidity(pairId [32]byte, to common.Address) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.ClaimLockedLiquidity(&_BondingCurveToken.TransactOpts, pairId, to)
}

// CreateBondingToken is a paid mutator transaction binding the contract method 0x35f9a856.
//
// Solidity: function createBondingToken(address _baseTokenAddress, string _name, string _symbol, uint8 _externalType, string _externalAddress, address _priceModel, uint256 _startPrice, uint256 _endPrice, uint256 _totalSupply, address _creatorAddress, address _affiliateAddress, address _burnAddress) returns(address newTokenAddress)
func (_BondingCurveToken *BondingCurveTokenTransactor) CreateBondingToken(opts *bind.TransactOpts, _baseTokenAddress common.Address, _name string, _symbol string, _externalType uint8, _externalAddress string, _priceModel common.Address, _startPrice *big.Int, _endPrice *big.Int, _totalSupply *big.Int, _creatorAddress common.Address, _affiliateAddress common.Address, _burnAddress common.Address) (*types.Transaction, error) {
	return _BondingCurveToken.contract.Transact(opts, "createBondingToken", _baseTokenAddress, _name, _symbol, _externalType, _externalAddress, _priceModel, _startPrice, _endPrice, _totalSupply, _creatorAddress, _affiliateAddress, _burnAddress)
}

// CreateBondingToken is a paid mutator transaction binding the contract method 0x35f9a856.
//
// Solidity: function createBondingToken(address _baseTokenAddress, string _name, string _symbol, uint8 _externalType, string _externalAddress, address _priceModel, uint256 _startPrice, uint256 _endPrice, uint256 _totalSupply, address _creatorAddress, address _affiliateAddress, address _burnAddress) returns(address newTokenAddress)
func (_BondingCurveToken *BondingCurveTokenSession) CreateBondingToken(_baseTokenAddress common.Address, _name string, _symbol string, _externalType uint8, _externalAddress string, _priceModel common.Address, _startPrice *big.Int, _endPrice *big.Int, _totalSupply *big.Int, _creatorAddress common.Address, _affiliateAddress common.Address, _burnAddress common.Address) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.CreateBondingToken(&_BondingCurveToken.TransactOpts, _baseTokenAddress, _name, _symbol, _externalType, _externalAddress, _priceModel, _startPrice, _endPrice, _totalSupply, _creatorAddress, _affiliateAddress, _burnAddress)
}

// CreateBondingToken is a paid mutator transaction binding the contract method 0x35f9a856.
//
// Solidity: function createBondingToken(address _baseTokenAddress, string _name, string _symbol, uint8 _externalType, string _externalAddress, address _priceModel, uint256 _startPrice, uint256 _endPrice, uint256 _totalSupply, address _creatorAddress, address _affiliateAddress, address _burnAddress) returns(address newTokenAddress)
func (_BondingCurveToken *BondingCurveTokenTransactorSession) CreateBondingToken(_baseTokenAddress common.Address, _name string, _symbol string, _externalType uint8, _externalAddress string, _priceModel common.Address, _startPrice *big.Int, _endPrice *big.Int, _totalSupply *big.Int, _creatorAddress common.Address, _affiliateAddress common.Address, _burnAddress common.Address) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.CreateBondingToken(&_BondingCurveToken.TransactOpts, _baseTokenAddress, _name, _symbol, _externalType, _externalAddress, _priceModel, _startPrice, _endPrice, _totalSupply, _creatorAddress, _affiliateAddress, _burnAddress)
}

// Initialize is a paid mutator transaction binding the contract method 0x3f1cc8d7.
//
// Solidity: function initialize(uint16 preMigrationFeeBps_, uint16 postMigrationFeeBps_, uint64 startTime_, address uniswapV3Router_, address uniswapV3Quoter_, address uniswapV3MigratorHelper_, address bondingTokenFactory_, address defaultPriceModel_, address uniswapTrader_, address uncxLockAdapter_) returns()
func (_BondingCurveToken *BondingCurveTokenTransactor) Initialize(opts *bind.TransactOpts, preMigrationFeeBps_ uint16, postMigrationFeeBps_ uint16, startTime_ uint64, uniswapV3Router_ common.Address, uniswapV3Quoter_ common.Address, uniswapV3MigratorHelper_ common.Address, bondingTokenFactory_ common.Address, defaultPriceModel_ common.Address, uniswapTrader_ common.Address, uncxLockAdapter_ common.Address) (*types.Transaction, error) {
	return _BondingCurveToken.contract.Transact(opts, "initialize", preMigrationFeeBps_, postMigrationFeeBps_, startTime_, uniswapV3Router_, uniswapV3Quoter_, uniswapV3MigratorHelper_, bondingTokenFactory_, defaultPriceModel_, uniswapTrader_, uncxLockAdapter_)
}

// Initialize is a paid mutator transaction binding the contract method 0x3f1cc8d7.
//
// Solidity: function initialize(uint16 preMigrationFeeBps_, uint16 postMigrationFeeBps_, uint64 startTime_, address uniswapV3Router_, address uniswapV3Quoter_, address uniswapV3MigratorHelper_, address bondingTokenFactory_, address defaultPriceModel_, address uniswapTrader_, address uncxLockAdapter_) returns()
func (_BondingCurveToken *BondingCurveTokenSession) Initialize(preMigrationFeeBps_ uint16, postMigrationFeeBps_ uint16, startTime_ uint64, uniswapV3Router_ common.Address, uniswapV3Quoter_ common.Address, uniswapV3MigratorHelper_ common.Address, bondingTokenFactory_ common.Address, defaultPriceModel_ common.Address, uniswapTrader_ common.Address, uncxLockAdapter_ common.Address) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.Initialize(&_BondingCurveToken.TransactOpts, preMigrationFeeBps_, postMigrationFeeBps_, startTime_, uniswapV3Router_, uniswapV3Quoter_, uniswapV3MigratorHelper_, bondingTokenFactory_, defaultPriceModel_, uniswapTrader_, uncxLockAdapter_)
}

// Initialize is a paid mutator transaction binding the contract method 0x3f1cc8d7.
//
// Solidity: function initialize(uint16 preMigrationFeeBps_, uint16 postMigrationFeeBps_, uint64 startTime_, address uniswapV3Router_, address uniswapV3Quoter_, address uniswapV3MigratorHelper_, address bondingTokenFactory_, address defaultPriceModel_, address uniswapTrader_, address uncxLockAdapter_) returns()
func (_BondingCurveToken *BondingCurveTokenTransactorSession) Initialize(preMigrationFeeBps_ uint16, postMigrationFeeBps_ uint16, startTime_ uint64, uniswapV3Router_ common.Address, uniswapV3Quoter_ common.Address, uniswapV3MigratorHelper_ common.Address, bondingTokenFactory_ common.Address, defaultPriceModel_ common.Address, uniswapTrader_ common.Address, uncxLockAdapter_ common.Address) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.Initialize(&_BondingCurveToken.TransactOpts, preMigrationFeeBps_, postMigrationFeeBps_, startTime_, uniswapV3Router_, uniswapV3Quoter_, uniswapV3MigratorHelper_, bondingTokenFactory_, defaultPriceModel_, uniswapTrader_, uncxLockAdapter_)
}

// Swap is a paid mutator transaction binding the contract method 0x027c101d.
//
// Solidity: function swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn, (uint256,uint256,uint8,bytes32,bytes32) permit) returns()
func (_BondingCurveToken *BondingCurveTokenTransactor) Swap(opts *bind.TransactOpts, fromToken []byte, toToken []byte, amountIn *big.Int, minReturn *big.Int, permit BondingCurvePermitData) (*types.Transaction, error) {
	return _BondingCurveToken.contract.Transact(opts, "swap", fromToken, toToken, amountIn, minReturn, permit)
}

// Swap is a paid mutator transaction binding the contract method 0x027c101d.
//
// Solidity: function swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn, (uint256,uint256,uint8,bytes32,bytes32) permit) returns()
func (_BondingCurveToken *BondingCurveTokenSession) Swap(fromToken []byte, toToken []byte, amountIn *big.Int, minReturn *big.Int, permit BondingCurvePermitData) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.Swap(&_BondingCurveToken.TransactOpts, fromToken, toToken, amountIn, minReturn, permit)
}

// Swap is a paid mutator transaction binding the contract method 0x027c101d.
//
// Solidity: function swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn, (uint256,uint256,uint8,bytes32,bytes32) permit) returns()
func (_BondingCurveToken *BondingCurveTokenTransactorSession) Swap(fromToken []byte, toToken []byte, amountIn *big.Int, minReturn *big.Int, permit BondingCurvePermitData) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.Swap(&_BondingCurveToken.TransactOpts, fromToken, toToken, amountIn, minReturn, permit)
}

// Swap0 is a paid mutator transaction binding the contract method 0x83362e17.
//
// Solidity: function swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn) returns()
func (_BondingCurveToken *BondingCurveTokenTransactor) Swap0(opts *bind.TransactOpts, fromToken []byte, toToken []byte, amountIn *big.Int, minReturn *big.Int) (*types.Transaction, error) {
	return _BondingCurveToken.contract.Transact(opts, "swap0", fromToken, toToken, amountIn, minReturn)
}

// Swap0 is a paid mutator transaction binding the contract method 0x83362e17.
//
// Solidity: function swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn) returns()
func (_BondingCurveToken *BondingCurveTokenSession) Swap0(fromToken []byte, toToken []byte, amountIn *big.Int, minReturn *big.Int) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.Swap0(&_BondingCurveToken.TransactOpts, fromToken, toToken, amountIn, minReturn)
}

// Swap0 is a paid mutator transaction binding the contract method 0x83362e17.
//
// Solidity: function swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn) returns()
func (_BondingCurveToken *BondingCurveTokenTransactorSession) Swap0(fromToken []byte, toToken []byte, amountIn *big.Int, minReturn *big.Int) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.Swap0(&_BondingCurveToken.TransactOpts, fromToken, toToken, amountIn, minReturn)
}

// BondingCurveTokenFeeAccruedIterator is returned from FilterFeeAccrued and is used to iterate over the raw logs and unpacked data for FeeAccrued events raised by the BondingCurveToken contract.
type BondingCurveTokenFeeAccruedIterator struct {
	Event *BondingCurveTokenFeeAccrued // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *BondingCurveTokenFeeAccruedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenFeeAccrued)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(BondingCurveTokenFeeAccrued)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *BondingCurveTokenFeeAccruedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenFeeAccruedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenFeeAccrued represents a FeeAccrued event raised by the BondingCurveToken contract.
type BondingCurveTokenFeeAccrued struct {
	PairId      [32]byte
	Payer       common.Address
	Fee         *big.Int
	ToCreator   *big.Int
	ToAffiliate *big.Int
	ToBurn      *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterFeeAccrued is a free log retrieval operation binding the contract event 0x7ac51ab75d98efed09beee76bda96ce115a6ad1ee184a9e0918d6a2f2a0354bb.
//
// Solidity: event FeeAccrued(bytes32 indexed pairId, address indexed payer, uint256 fee, uint256 toCreator, uint256 toAffiliate, uint256 toBurn)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterFeeAccrued(opts *bind.FilterOpts, pairId [][32]byte, payer []common.Address) (*BondingCurveTokenFeeAccruedIterator, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}
	var payerRule []interface{}
	for _, payerItem := range payer {
		payerRule = append(payerRule, payerItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "FeeAccrued", pairIdRule, payerRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenFeeAccruedIterator{contract: _BondingCurveToken.contract, event: "FeeAccrued", logs: logs, sub: sub}, nil
}

// WatchFeeAccrued is a free log subscription operation binding the contract event 0x7ac51ab75d98efed09beee76bda96ce115a6ad1ee184a9e0918d6a2f2a0354bb.
//
// Solidity: event FeeAccrued(bytes32 indexed pairId, address indexed payer, uint256 fee, uint256 toCreator, uint256 toAffiliate, uint256 toBurn)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchFeeAccrued(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenFeeAccrued, pairId [][32]byte, payer []common.Address) (event.Subscription, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}
	var payerRule []interface{}
	for _, payerItem := range payer {
		payerRule = append(payerRule, payerItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "FeeAccrued", pairIdRule, payerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenFeeAccrued)
				if err := _BondingCurveToken.contract.UnpackLog(event, "FeeAccrued", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseFeeAccrued is a log parse operation binding the contract event 0x7ac51ab75d98efed09beee76bda96ce115a6ad1ee184a9e0918d6a2f2a0354bb.
//
// Solidity: event FeeAccrued(bytes32 indexed pairId, address indexed payer, uint256 fee, uint256 toCreator, uint256 toAffiliate, uint256 toBurn)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseFeeAccrued(log types.Log) (*BondingCurveTokenFeeAccrued, error) {
	event := new(BondingCurveTokenFeeAccrued)
	if err := _BondingCurveToken.contract.UnpackLog(event, "FeeAccrued", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BondingCurveTokenFeeTransferIterator is returned from FilterFeeTransfer and is used to iterate over the raw logs and unpacked data for FeeTransfer events raised by the BondingCurveToken contract.
type BondingCurveTokenFeeTransferIterator struct {
	Event *BondingCurveTokenFeeTransfer // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *BondingCurveTokenFeeTransferIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenFeeTransfer)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(BondingCurveTokenFeeTransfer)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *BondingCurveTokenFeeTransferIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenFeeTransferIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenFeeTransfer represents a FeeTransfer event raised by the BondingCurveToken contract.
type BondingCurveTokenFeeTransfer struct {
	PairId [32]byte
	To     common.Address
	Amount *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterFeeTransfer is a free log retrieval operation binding the contract event 0xbda77c1230f2354807b9e8307932c78ac43f6b38ea2e10d9886aa30c958300f5.
//
// Solidity: event FeeTransfer(bytes32 indexed pairId, address indexed to, uint256 amount)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterFeeTransfer(opts *bind.FilterOpts, pairId [][32]byte, to []common.Address) (*BondingCurveTokenFeeTransferIterator, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "FeeTransfer", pairIdRule, toRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenFeeTransferIterator{contract: _BondingCurveToken.contract, event: "FeeTransfer", logs: logs, sub: sub}, nil
}

// WatchFeeTransfer is a free log subscription operation binding the contract event 0xbda77c1230f2354807b9e8307932c78ac43f6b38ea2e10d9886aa30c958300f5.
//
// Solidity: event FeeTransfer(bytes32 indexed pairId, address indexed to, uint256 amount)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchFeeTransfer(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenFeeTransfer, pairId [][32]byte, to []common.Address) (event.Subscription, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "FeeTransfer", pairIdRule, toRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenFeeTransfer)
				if err := _BondingCurveToken.contract.UnpackLog(event, "FeeTransfer", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseFeeTransfer is a log parse operation binding the contract event 0xbda77c1230f2354807b9e8307932c78ac43f6b38ea2e10d9886aa30c958300f5.
//
// Solidity: event FeeTransfer(bytes32 indexed pairId, address indexed to, uint256 amount)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseFeeTransfer(log types.Log) (*BondingCurveTokenFeeTransfer, error) {
	event := new(BondingCurveTokenFeeTransfer)
	if err := _BondingCurveToken.contract.UnpackLog(event, "FeeTransfer", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BondingCurveTokenPairRegisteredIterator is returned from FilterPairRegistered and is used to iterate over the raw logs and unpacked data for PairRegistered events raised by the BondingCurveToken contract.
type BondingCurveTokenPairRegisteredIterator struct {
	Event *BondingCurveTokenPairRegistered // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *BondingCurveTokenPairRegisteredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenPairRegistered)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(BondingCurveTokenPairRegistered)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *BondingCurveTokenPairRegisteredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenPairRegisteredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenPairRegistered represents a PairRegistered event raised by the BondingCurveToken contract.
type BondingCurveTokenPairRegistered struct {
	PairId          [32]byte
	BaseToken       common.Address
	OtherToken      common.Address
	FeeIsOtherToken bool
	PriceModel      common.Address
	StartPrice      *big.Int
	EndPrice        *big.Int
	Raw             types.Log // Blockchain specific contextual infos
}

// FilterPairRegistered is a free log retrieval operation binding the contract event 0x908a4168fc7576885b681f3b0594297fa8118a2bca55899ac9ef3229438dbb04.
//
// Solidity: event PairRegistered(bytes32 indexed pairId, address indexed baseToken, address indexed otherToken, bool feeIsOtherToken, address priceModel, uint256 startPrice, uint256 endPrice)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterPairRegistered(opts *bind.FilterOpts, pairId [][32]byte, baseToken []common.Address, otherToken []common.Address) (*BondingCurveTokenPairRegisteredIterator, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}
	var baseTokenRule []interface{}
	for _, baseTokenItem := range baseToken {
		baseTokenRule = append(baseTokenRule, baseTokenItem)
	}
	var otherTokenRule []interface{}
	for _, otherTokenItem := range otherToken {
		otherTokenRule = append(otherTokenRule, otherTokenItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "PairRegistered", pairIdRule, baseTokenRule, otherTokenRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenPairRegisteredIterator{contract: _BondingCurveToken.contract, event: "PairRegistered", logs: logs, sub: sub}, nil
}

// WatchPairRegistered is a free log subscription operation binding the contract event 0x908a4168fc7576885b681f3b0594297fa8118a2bca55899ac9ef3229438dbb04.
//
// Solidity: event PairRegistered(bytes32 indexed pairId, address indexed baseToken, address indexed otherToken, bool feeIsOtherToken, address priceModel, uint256 startPrice, uint256 endPrice)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchPairRegistered(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenPairRegistered, pairId [][32]byte, baseToken []common.Address, otherToken []common.Address) (event.Subscription, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}
	var baseTokenRule []interface{}
	for _, baseTokenItem := range baseToken {
		baseTokenRule = append(baseTokenRule, baseTokenItem)
	}
	var otherTokenRule []interface{}
	for _, otherTokenItem := range otherToken {
		otherTokenRule = append(otherTokenRule, otherTokenItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "PairRegistered", pairIdRule, baseTokenRule, otherTokenRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenPairRegistered)
				if err := _BondingCurveToken.contract.UnpackLog(event, "PairRegistered", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePairRegistered is a log parse operation binding the contract event 0x908a4168fc7576885b681f3b0594297fa8118a2bca55899ac9ef3229438dbb04.
//
// Solidity: event PairRegistered(bytes32 indexed pairId, address indexed baseToken, address indexed otherToken, bool feeIsOtherToken, address priceModel, uint256 startPrice, uint256 endPrice)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParsePairRegistered(log types.Log) (*BondingCurveTokenPairRegistered, error) {
	event := new(BondingCurveTokenPairRegistered)
	if err := _BondingCurveToken.contract.UnpackLog(event, "PairRegistered", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BondingCurveTokenRecipientsSetIterator is returned from FilterRecipientsSet and is used to iterate over the raw logs and unpacked data for RecipientsSet events raised by the BondingCurveToken contract.
type BondingCurveTokenRecipientsSetIterator struct {
	Event *BondingCurveTokenRecipientsSet // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *BondingCurveTokenRecipientsSetIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenRecipientsSet)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(BondingCurveTokenRecipientsSet)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *BondingCurveTokenRecipientsSetIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenRecipientsSetIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenRecipientsSet represents a RecipientsSet event raised by the BondingCurveToken contract.
type BondingCurveTokenRecipientsSet struct {
	PairId    [32]byte
	Creator   common.Address
	Affiliate common.Address
	Burn      common.Address
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterRecipientsSet is a free log retrieval operation binding the contract event 0xc391f1439e6a5d64454067a61cc30295e026850c66d0dcb87e5c74c455862408.
//
// Solidity: event RecipientsSet(bytes32 indexed pairId, address creator, address affiliate, address burn)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterRecipientsSet(opts *bind.FilterOpts, pairId [][32]byte) (*BondingCurveTokenRecipientsSetIterator, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "RecipientsSet", pairIdRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenRecipientsSetIterator{contract: _BondingCurveToken.contract, event: "RecipientsSet", logs: logs, sub: sub}, nil
}

// WatchRecipientsSet is a free log subscription operation binding the contract event 0xc391f1439e6a5d64454067a61cc30295e026850c66d0dcb87e5c74c455862408.
//
// Solidity: event RecipientsSet(bytes32 indexed pairId, address creator, address affiliate, address burn)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchRecipientsSet(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenRecipientsSet, pairId [][32]byte) (event.Subscription, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "RecipientsSet", pairIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenRecipientsSet)
				if err := _BondingCurveToken.contract.UnpackLog(event, "RecipientsSet", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRecipientsSet is a log parse operation binding the contract event 0xc391f1439e6a5d64454067a61cc30295e026850c66d0dcb87e5c74c455862408.
//
// Solidity: event RecipientsSet(bytes32 indexed pairId, address creator, address affiliate, address burn)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseRecipientsSet(log types.Log) (*BondingCurveTokenRecipientsSet, error) {
	event := new(BondingCurveTokenRecipientsSet)
	if err := _BondingCurveToken.contract.UnpackLog(event, "RecipientsSet", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BondingCurveTokenSlippageCheckedIterator is returned from FilterSlippageChecked and is used to iterate over the raw logs and unpacked data for SlippageChecked events raised by the BondingCurveToken contract.
type BondingCurveTokenSlippageCheckedIterator struct {
	Event *BondingCurveTokenSlippageChecked // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *BondingCurveTokenSlippageCheckedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenSlippageChecked)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(BondingCurveTokenSlippageChecked)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *BondingCurveTokenSlippageCheckedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenSlippageCheckedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenSlippageChecked represents a SlippageChecked event raised by the BondingCurveToken contract.
type BondingCurveTokenSlippageChecked struct {
	PairId    [32]byte
	MinReturn *big.Int
	ActualOut *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterSlippageChecked is a free log retrieval operation binding the contract event 0x65184e4e64eca5b9cd1401ff3001ac8803c660b9ac3bf7af10b7fae4b146b446.
//
// Solidity: event SlippageChecked(bytes32 indexed pairId, uint256 minReturn, uint256 actualOut)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterSlippageChecked(opts *bind.FilterOpts, pairId [][32]byte) (*BondingCurveTokenSlippageCheckedIterator, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "SlippageChecked", pairIdRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenSlippageCheckedIterator{contract: _BondingCurveToken.contract, event: "SlippageChecked", logs: logs, sub: sub}, nil
}

// WatchSlippageChecked is a free log subscription operation binding the contract event 0x65184e4e64eca5b9cd1401ff3001ac8803c660b9ac3bf7af10b7fae4b146b446.
//
// Solidity: event SlippageChecked(bytes32 indexed pairId, uint256 minReturn, uint256 actualOut)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchSlippageChecked(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenSlippageChecked, pairId [][32]byte) (event.Subscription, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "SlippageChecked", pairIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenSlippageChecked)
				if err := _BondingCurveToken.contract.UnpackLog(event, "SlippageChecked", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSlippageChecked is a log parse operation binding the contract event 0x65184e4e64eca5b9cd1401ff3001ac8803c660b9ac3bf7af10b7fae4b146b446.
//
// Solidity: event SlippageChecked(bytes32 indexed pairId, uint256 minReturn, uint256 actualOut)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseSlippageChecked(log types.Log) (*BondingCurveTokenSlippageChecked, error) {
	event := new(BondingCurveTokenSlippageChecked)
	if err := _BondingCurveToken.contract.UnpackLog(event, "SlippageChecked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BondingCurveTokenSwappedIterator is returned from FilterSwapped and is used to iterate over the raw logs and unpacked data for Swapped events raised by the BondingCurveToken contract.
type BondingCurveTokenSwappedIterator struct {
	Event *BondingCurveTokenSwapped // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *BondingCurveTokenSwappedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenSwapped)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(BondingCurveTokenSwapped)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *BondingCurveTokenSwappedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenSwappedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenSwapped represents a Swapped event raised by the BondingCurveToken contract.
type BondingCurveTokenSwapped struct {
	Swapper      common.Address
	PairId       [32]byte
	Direction    bool
	InputAmount  *big.Int
	OutputAmount *big.Int
	Fee          *big.Int
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterSwapped is a free log retrieval operation binding the contract event 0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0.
//
// Solidity: event Swapped(address indexed swapper, bytes32 indexed pairId, bool direction, uint256 inputAmount, uint256 outputAmount, uint256 fee)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterSwapped(opts *bind.FilterOpts, swapper []common.Address, pairId [][32]byte) (*BondingCurveTokenSwappedIterator, error) {

	var swapperRule []interface{}
	for _, swapperItem := range swapper {
		swapperRule = append(swapperRule, swapperItem)
	}
	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "Swapped", swapperRule, pairIdRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenSwappedIterator{contract: _BondingCurveToken.contract, event: "Swapped", logs: logs, sub: sub}, nil
}

// WatchSwapped is a free log subscription operation binding the contract event 0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0.
//
// Solidity: event Swapped(address indexed swapper, bytes32 indexed pairId, bool direction, uint256 inputAmount, uint256 outputAmount, uint256 fee)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchSwapped(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenSwapped, swapper []common.Address, pairId [][32]byte) (event.Subscription, error) {

	var swapperRule []interface{}
	for _, swapperItem := range swapper {
		swapperRule = append(swapperRule, swapperItem)
	}
	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "Swapped", swapperRule, pairIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenSwapped)
				if err := _BondingCurveToken.contract.UnpackLog(event, "Swapped", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSwapped is a log parse operation binding the contract event 0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0.
//
// Solidity: event Swapped(address indexed swapper, bytes32 indexed pairId, bool direction, uint256 inputAmount, uint256 outputAmount, uint256 fee)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseSwapped(log types.Log) (*BondingCurveTokenSwapped, error) {
	event := new(BondingCurveTokenSwapped)
	if err := _BondingCurveToken.contract.UnpackLog(event, "Swapped", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
