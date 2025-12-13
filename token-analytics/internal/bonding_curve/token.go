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

// UniswapV3MigratorMigrationInfo is an auto generated low-level Go binding around an user-defined struct.
type UniswapV3MigratorMigrationInfo struct {
	Migrated              bool
	Pool                  common.Address
	LpToken               common.Address
	LockedLiquidityAmount *big.Int
}

// BondingCurveTokenMetaData contains all meta data concerning the BondingCurveToken contract.
var BondingCurveTokenMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"uint16\",\"name\":\"feeBps_\",\"type\":\"uint16\"},{\"internalType\":\"uint64\",\"name\":\"startTime_\",\"type\":\"uint64\"},{\"internalType\":\"address\",\"name\":\"uniswapV3Factory_\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"Allowance\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"DoubleCreate\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"EmptyRecipients\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InsufficientFeeBalance\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvalidBps\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvalidExternalData\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"NotCreator\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"NotUnlockedYet\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"PairDoesNotExist\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"minReturn\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"tokenOut\",\"type\":\"uint256\"}],\"name\":\"SlippageTooHigh\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"TokenNotMapped\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"TokenSelector\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"ZeroAddress\",\"type\":\"error\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"tokenAddress\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"name\",\"type\":\"string\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"symbol\",\"type\":\"string\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"externalAddress\",\"type\":\"string\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"totalSupply\",\"type\":\"uint256\"}],\"name\":\"BondingTokenCreated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"payer\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"fee\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"toCreator\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"toAffiliate\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"toBurn\",\"type\":\"uint256\"}],\"name\":\"FeeAccrued\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"FeeTransfer\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"LiquidityClaimed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"lpToken\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"unlockTime\",\"type\":\"uint256\"}],\"name\":\"LiquidityLocked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"pool\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"lockedLiquidityAmount\",\"type\":\"uint256\"}],\"name\":\"Migrated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"baseToken\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"otherToken\",\"type\":\"address\"}],\"name\":\"PairRegistered\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"affiliate\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"burn\",\"type\":\"address\"}],\"name\":\"RecipientsSet\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"reason\",\"type\":\"bytes32\"}],\"name\":\"RefundIssued\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"router\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"path\",\"type\":\"address[]\"}],\"name\":\"RouteSelected\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"minReturn\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"actualOut\",\"type\":\"uint256\"}],\"name\":\"SlippageChecked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"swapper\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"direction\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"inputAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"outputAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"fee\",\"type\":\"uint256\"}],\"name\":\"Swapped\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"passed\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"reasonCode\",\"type\":\"uint8\"}],\"name\":\"VerificationChecked\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"}],\"name\":\"bondingProgress\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"soldTokens\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"tokensRaised\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"startPrice\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"endPrice\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"bondingTokensGoal\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"currentPrice\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"migrated\",\"type\":\"bool\"}],\"internalType\":\"structBondingCurve.BondingInfo\",\"name\":\"info\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"}],\"name\":\"claimLockedLiquidity\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"config\",\"outputs\":[{\"internalType\":\"uint16\",\"name\":\"feeBps\",\"type\":\"uint16\"},{\"internalType\":\"uint64\",\"name\":\"startTime\",\"type\":\"uint64\"},{\"internalType\":\"uint64\",\"name\":\"rampDuration\",\"type\":\"uint64\"},{\"internalType\":\"uint16\",\"name\":\"startCreatorBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"startAffiliateBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"startBurnBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"endCreatorBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"endAffiliateBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"endBurnBps\",\"type\":\"uint16\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"_name\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"_symbol\",\"type\":\"string\"},{\"internalType\":\"address\",\"name\":\"_creator\",\"type\":\"address\"},{\"internalType\":\"string\",\"name\":\"_externalAddress\",\"type\":\"string\"},{\"internalType\":\"address\",\"name\":\"_baseTokenAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_totalSupply\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"_creatorAddress\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_affiliateAddress\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_burnAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_startPrice\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_endPrice\",\"type\":\"uint256\"}],\"name\":\"createBondingToken\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"name\":\"externalAddressToToken\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"feePercentages\",\"outputs\":[{\"internalType\":\"uint16\",\"name\":\"cBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"aBps\",\"type\":\"uint16\"},{\"internalType\":\"uint16\",\"name\":\"bBps\",\"type\":\"uint16\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"}],\"name\":\"fees\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"creatorAccrued\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"affiliateAccrued\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"burnAccrued\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"}],\"name\":\"getAccrued\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"creatorAccrued\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"affiliateAccrued\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"burnAccrued\",\"type\":\"uint256\"}],\"internalType\":\"structFeePolicy.FeeBuckets\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"}],\"name\":\"getRecipients\",\"outputs\":[{\"components\":[{\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"affiliate\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"burn\",\"type\":\"address\"}],\"internalType\":\"structFeePolicy.Recipients\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"pairId\",\"type\":\"bytes32\"}],\"name\":\"migrationOf\",\"outputs\":[{\"components\":[{\"internalType\":\"bool\",\"name\":\"migrated\",\"type\":\"bool\"},{\"internalType\":\"address\",\"name\":\"pool\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"lpToken\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"lockedLiquidityAmount\",\"type\":\"uint256\"}],\"internalType\":\"structUniswapV3Migrator.MigrationInfo\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"a\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"b\",\"type\":\"address\"}],\"name\":\"pairIdOf\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"pairs\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"baseTokenAddress\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"otherTokenAddress\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"startPrice\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"endPrice\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"fromToken\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"toToken\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"amountInBase\",\"type\":\"uint256\"}],\"name\":\"quoteBuyOut\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"amountOutOther\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"fromToken\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"toToken\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"amountInOther\",\"type\":\"uint256\"}],\"name\":\"quoteSellOut\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"amountOutBase\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"fromToken\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"toToken\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"amountIn\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"minReturn\",\"type\":\"uint256\"}],\"name\":\"swap\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
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

// Config is a free data retrieval call binding the contract method 0x79502c55.
//
// Solidity: function config() view returns(uint16 feeBps, uint64 startTime, uint64 rampDuration, uint16 startCreatorBps, uint16 startAffiliateBps, uint16 startBurnBps, uint16 endCreatorBps, uint16 endAffiliateBps, uint16 endBurnBps)
func (_BondingCurveToken *BondingCurveTokenCaller) Config(opts *bind.CallOpts) (struct {
	FeeBps            uint16
	StartTime         uint64
	RampDuration      uint64
	StartCreatorBps   uint16
	StartAffiliateBps uint16
	StartBurnBps      uint16
	EndCreatorBps     uint16
	EndAffiliateBps   uint16
	EndBurnBps        uint16
}, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "config")

	outstruct := new(struct {
		FeeBps            uint16
		StartTime         uint64
		RampDuration      uint64
		StartCreatorBps   uint16
		StartAffiliateBps uint16
		StartBurnBps      uint16
		EndCreatorBps     uint16
		EndAffiliateBps   uint16
		EndBurnBps        uint16
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.FeeBps = *abi.ConvertType(out[0], new(uint16)).(*uint16)
	outstruct.StartTime = *abi.ConvertType(out[1], new(uint64)).(*uint64)
	outstruct.RampDuration = *abi.ConvertType(out[2], new(uint64)).(*uint64)
	outstruct.StartCreatorBps = *abi.ConvertType(out[3], new(uint16)).(*uint16)
	outstruct.StartAffiliateBps = *abi.ConvertType(out[4], new(uint16)).(*uint16)
	outstruct.StartBurnBps = *abi.ConvertType(out[5], new(uint16)).(*uint16)
	outstruct.EndCreatorBps = *abi.ConvertType(out[6], new(uint16)).(*uint16)
	outstruct.EndAffiliateBps = *abi.ConvertType(out[7], new(uint16)).(*uint16)
	outstruct.EndBurnBps = *abi.ConvertType(out[8], new(uint16)).(*uint16)

	return *outstruct, err

}

// Config is a free data retrieval call binding the contract method 0x79502c55.
//
// Solidity: function config() view returns(uint16 feeBps, uint64 startTime, uint64 rampDuration, uint16 startCreatorBps, uint16 startAffiliateBps, uint16 startBurnBps, uint16 endCreatorBps, uint16 endAffiliateBps, uint16 endBurnBps)
func (_BondingCurveToken *BondingCurveTokenSession) Config() (struct {
	FeeBps            uint16
	StartTime         uint64
	RampDuration      uint64
	StartCreatorBps   uint16
	StartAffiliateBps uint16
	StartBurnBps      uint16
	EndCreatorBps     uint16
	EndAffiliateBps   uint16
	EndBurnBps        uint16
}, error) {
	return _BondingCurveToken.Contract.Config(&_BondingCurveToken.CallOpts)
}

// Config is a free data retrieval call binding the contract method 0x79502c55.
//
// Solidity: function config() view returns(uint16 feeBps, uint64 startTime, uint64 rampDuration, uint16 startCreatorBps, uint16 startAffiliateBps, uint16 startBurnBps, uint16 endCreatorBps, uint16 endAffiliateBps, uint16 endBurnBps)
func (_BondingCurveToken *BondingCurveTokenCallerSession) Config() (struct {
	FeeBps            uint16
	StartTime         uint64
	RampDuration      uint64
	StartCreatorBps   uint16
	StartAffiliateBps uint16
	StartBurnBps      uint16
	EndCreatorBps     uint16
	EndAffiliateBps   uint16
	EndBurnBps        uint16
}, error) {
	return _BondingCurveToken.Contract.Config(&_BondingCurveToken.CallOpts)
}

// ExternalAddressToToken is a free data retrieval call binding the contract method 0x7ec25be8.
//
// Solidity: function externalAddressToToken(string ) view returns(address)
func (_BondingCurveToken *BondingCurveTokenCaller) ExternalAddressToToken(opts *bind.CallOpts, arg0 string) (common.Address, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "externalAddressToToken", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// ExternalAddressToToken is a free data retrieval call binding the contract method 0x7ec25be8.
//
// Solidity: function externalAddressToToken(string ) view returns(address)
func (_BondingCurveToken *BondingCurveTokenSession) ExternalAddressToToken(arg0 string) (common.Address, error) {
	return _BondingCurveToken.Contract.ExternalAddressToToken(&_BondingCurveToken.CallOpts, arg0)
}

// ExternalAddressToToken is a free data retrieval call binding the contract method 0x7ec25be8.
//
// Solidity: function externalAddressToToken(string ) view returns(address)
func (_BondingCurveToken *BondingCurveTokenCallerSession) ExternalAddressToToken(arg0 string) (common.Address, error) {
	return _BondingCurveToken.Contract.ExternalAddressToToken(&_BondingCurveToken.CallOpts, arg0)
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
// Solidity: function migrationOf(bytes32 pairId) view returns((bool,address,address,uint256))
func (_BondingCurveToken *BondingCurveTokenCaller) MigrationOf(opts *bind.CallOpts, pairId [32]byte) (UniswapV3MigratorMigrationInfo, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "migrationOf", pairId)

	if err != nil {
		return *new(UniswapV3MigratorMigrationInfo), err
	}

	out0 := *abi.ConvertType(out[0], new(UniswapV3MigratorMigrationInfo)).(*UniswapV3MigratorMigrationInfo)

	return out0, err

}

// MigrationOf is a free data retrieval call binding the contract method 0x2fa9c64e.
//
// Solidity: function migrationOf(bytes32 pairId) view returns((bool,address,address,uint256))
func (_BondingCurveToken *BondingCurveTokenSession) MigrationOf(pairId [32]byte) (UniswapV3MigratorMigrationInfo, error) {
	return _BondingCurveToken.Contract.MigrationOf(&_BondingCurveToken.CallOpts, pairId)
}

// MigrationOf is a free data retrieval call binding the contract method 0x2fa9c64e.
//
// Solidity: function migrationOf(bytes32 pairId) view returns((bool,address,address,uint256))
func (_BondingCurveToken *BondingCurveTokenCallerSession) MigrationOf(pairId [32]byte) (UniswapV3MigratorMigrationInfo, error) {
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
// Solidity: function pairs(bytes32 ) view returns(address baseTokenAddress, address otherTokenAddress, address creator, uint256 startPrice, uint256 endPrice)
func (_BondingCurveToken *BondingCurveTokenCaller) Pairs(opts *bind.CallOpts, arg0 [32]byte) (struct {
	BaseTokenAddress  common.Address
	OtherTokenAddress common.Address
	Creator           common.Address
	StartPrice        *big.Int
	EndPrice          *big.Int
}, error) {
	var out []interface{}
	err := _BondingCurveToken.contract.Call(opts, &out, "pairs", arg0)

	outstruct := new(struct {
		BaseTokenAddress  common.Address
		OtherTokenAddress common.Address
		Creator           common.Address
		StartPrice        *big.Int
		EndPrice          *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.BaseTokenAddress = *abi.ConvertType(out[0], new(common.Address)).(*common.Address)
	outstruct.OtherTokenAddress = *abi.ConvertType(out[1], new(common.Address)).(*common.Address)
	outstruct.Creator = *abi.ConvertType(out[2], new(common.Address)).(*common.Address)
	outstruct.StartPrice = *abi.ConvertType(out[3], new(*big.Int)).(**big.Int)
	outstruct.EndPrice = *abi.ConvertType(out[4], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// Pairs is a free data retrieval call binding the contract method 0x673e0481.
//
// Solidity: function pairs(bytes32 ) view returns(address baseTokenAddress, address otherTokenAddress, address creator, uint256 startPrice, uint256 endPrice)
func (_BondingCurveToken *BondingCurveTokenSession) Pairs(arg0 [32]byte) (struct {
	BaseTokenAddress  common.Address
	OtherTokenAddress common.Address
	Creator           common.Address
	StartPrice        *big.Int
	EndPrice          *big.Int
}, error) {
	return _BondingCurveToken.Contract.Pairs(&_BondingCurveToken.CallOpts, arg0)
}

// Pairs is a free data retrieval call binding the contract method 0x673e0481.
//
// Solidity: function pairs(bytes32 ) view returns(address baseTokenAddress, address otherTokenAddress, address creator, uint256 startPrice, uint256 endPrice)
func (_BondingCurveToken *BondingCurveTokenCallerSession) Pairs(arg0 [32]byte) (struct {
	BaseTokenAddress  common.Address
	OtherTokenAddress common.Address
	Creator           common.Address
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

// CreateBondingToken is a paid mutator transaction binding the contract method 0x1a71691c.
//
// Solidity: function createBondingToken(string _name, string _symbol, address _creator, string _externalAddress, address _baseTokenAddress, uint256 _totalSupply, address _creatorAddress, address _affiliateAddress, address _burnAddress, uint256 _startPrice, uint256 _endPrice) returns(address)
func (_BondingCurveToken *BondingCurveTokenTransactor) CreateBondingToken(opts *bind.TransactOpts, _name string, _symbol string, _creator common.Address, _externalAddress string, _baseTokenAddress common.Address, _totalSupply *big.Int, _creatorAddress common.Address, _affiliateAddress common.Address, _burnAddress common.Address, _startPrice *big.Int, _endPrice *big.Int) (*types.Transaction, error) {
	return _BondingCurveToken.contract.Transact(opts, "createBondingToken", _name, _symbol, _creator, _externalAddress, _baseTokenAddress, _totalSupply, _creatorAddress, _affiliateAddress, _burnAddress, _startPrice, _endPrice)
}

// CreateBondingToken is a paid mutator transaction binding the contract method 0x1a71691c.
//
// Solidity: function createBondingToken(string _name, string _symbol, address _creator, string _externalAddress, address _baseTokenAddress, uint256 _totalSupply, address _creatorAddress, address _affiliateAddress, address _burnAddress, uint256 _startPrice, uint256 _endPrice) returns(address)
func (_BondingCurveToken *BondingCurveTokenSession) CreateBondingToken(_name string, _symbol string, _creator common.Address, _externalAddress string, _baseTokenAddress common.Address, _totalSupply *big.Int, _creatorAddress common.Address, _affiliateAddress common.Address, _burnAddress common.Address, _startPrice *big.Int, _endPrice *big.Int) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.CreateBondingToken(&_BondingCurveToken.TransactOpts, _name, _symbol, _creator, _externalAddress, _baseTokenAddress, _totalSupply, _creatorAddress, _affiliateAddress, _burnAddress, _startPrice, _endPrice)
}

// CreateBondingToken is a paid mutator transaction binding the contract method 0x1a71691c.
//
// Solidity: function createBondingToken(string _name, string _symbol, address _creator, string _externalAddress, address _baseTokenAddress, uint256 _totalSupply, address _creatorAddress, address _affiliateAddress, address _burnAddress, uint256 _startPrice, uint256 _endPrice) returns(address)
func (_BondingCurveToken *BondingCurveTokenTransactorSession) CreateBondingToken(_name string, _symbol string, _creator common.Address, _externalAddress string, _baseTokenAddress common.Address, _totalSupply *big.Int, _creatorAddress common.Address, _affiliateAddress common.Address, _burnAddress common.Address, _startPrice *big.Int, _endPrice *big.Int) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.CreateBondingToken(&_BondingCurveToken.TransactOpts, _name, _symbol, _creator, _externalAddress, _baseTokenAddress, _totalSupply, _creatorAddress, _affiliateAddress, _burnAddress, _startPrice, _endPrice)
}

// Swap is a paid mutator transaction binding the contract method 0x83362e17.
//
// Solidity: function swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn) returns()
func (_BondingCurveToken *BondingCurveTokenTransactor) Swap(opts *bind.TransactOpts, fromToken []byte, toToken []byte, amountIn *big.Int, minReturn *big.Int) (*types.Transaction, error) {
	return _BondingCurveToken.contract.Transact(opts, "swap", fromToken, toToken, amountIn, minReturn)
}

// Swap is a paid mutator transaction binding the contract method 0x83362e17.
//
// Solidity: function swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn) returns()
func (_BondingCurveToken *BondingCurveTokenSession) Swap(fromToken []byte, toToken []byte, amountIn *big.Int, minReturn *big.Int) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.Swap(&_BondingCurveToken.TransactOpts, fromToken, toToken, amountIn, minReturn)
}

// Swap is a paid mutator transaction binding the contract method 0x83362e17.
//
// Solidity: function swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn) returns()
func (_BondingCurveToken *BondingCurveTokenTransactorSession) Swap(fromToken []byte, toToken []byte, amountIn *big.Int, minReturn *big.Int) (*types.Transaction, error) {
	return _BondingCurveToken.Contract.Swap(&_BondingCurveToken.TransactOpts, fromToken, toToken, amountIn, minReturn)
}

// BondingCurveTokenBondingTokenCreatedIterator is returned from FilterBondingTokenCreated and is used to iterate over the raw logs and unpacked data for BondingTokenCreated events raised by the BondingCurveToken contract.
type BondingCurveTokenBondingTokenCreatedIterator struct {
	Event *BondingCurveTokenBondingTokenCreated // Event containing the contract specifics and raw log

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
func (it *BondingCurveTokenBondingTokenCreatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenBondingTokenCreated)
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
		it.Event = new(BondingCurveTokenBondingTokenCreated)
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
func (it *BondingCurveTokenBondingTokenCreatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenBondingTokenCreatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenBondingTokenCreated represents a BondingTokenCreated event raised by the BondingCurveToken contract.
type BondingCurveTokenBondingTokenCreated struct {
	TokenAddress    common.Address
	Name            string
	Symbol          string
	ExternalAddress string
	TotalSupply     *big.Int
	Raw             types.Log // Blockchain specific contextual infos
}

// FilterBondingTokenCreated is a free log retrieval operation binding the contract event 0x7a69aeb15d1aa44b3fec40fc8767221a5e4d2f41e58421d34db80a63f5a619c7.
//
// Solidity: event BondingTokenCreated(address indexed tokenAddress, string name, string symbol, string externalAddress, uint256 totalSupply)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterBondingTokenCreated(opts *bind.FilterOpts, tokenAddress []common.Address) (*BondingCurveTokenBondingTokenCreatedIterator, error) {

	var tokenAddressRule []interface{}
	for _, tokenAddressItem := range tokenAddress {
		tokenAddressRule = append(tokenAddressRule, tokenAddressItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "BondingTokenCreated", tokenAddressRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenBondingTokenCreatedIterator{contract: _BondingCurveToken.contract, event: "BondingTokenCreated", logs: logs, sub: sub}, nil
}

// WatchBondingTokenCreated is a free log subscription operation binding the contract event 0x7a69aeb15d1aa44b3fec40fc8767221a5e4d2f41e58421d34db80a63f5a619c7.
//
// Solidity: event BondingTokenCreated(address indexed tokenAddress, string name, string symbol, string externalAddress, uint256 totalSupply)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchBondingTokenCreated(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenBondingTokenCreated, tokenAddress []common.Address) (event.Subscription, error) {

	var tokenAddressRule []interface{}
	for _, tokenAddressItem := range tokenAddress {
		tokenAddressRule = append(tokenAddressRule, tokenAddressItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "BondingTokenCreated", tokenAddressRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenBondingTokenCreated)
				if err := _BondingCurveToken.contract.UnpackLog(event, "BondingTokenCreated", log); err != nil {
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

// ParseBondingTokenCreated is a log parse operation binding the contract event 0x7a69aeb15d1aa44b3fec40fc8767221a5e4d2f41e58421d34db80a63f5a619c7.
//
// Solidity: event BondingTokenCreated(address indexed tokenAddress, string name, string symbol, string externalAddress, uint256 totalSupply)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseBondingTokenCreated(log types.Log) (*BondingCurveTokenBondingTokenCreated, error) {
	event := new(BondingCurveTokenBondingTokenCreated)
	if err := _BondingCurveToken.contract.UnpackLog(event, "BondingTokenCreated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
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

// BondingCurveTokenLiquidityClaimedIterator is returned from FilterLiquidityClaimed and is used to iterate over the raw logs and unpacked data for LiquidityClaimed events raised by the BondingCurveToken contract.
type BondingCurveTokenLiquidityClaimedIterator struct {
	Event *BondingCurveTokenLiquidityClaimed // Event containing the contract specifics and raw log

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
func (it *BondingCurveTokenLiquidityClaimedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenLiquidityClaimed)
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
		it.Event = new(BondingCurveTokenLiquidityClaimed)
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
func (it *BondingCurveTokenLiquidityClaimedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenLiquidityClaimedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenLiquidityClaimed represents a LiquidityClaimed event raised by the BondingCurveToken contract.
type BondingCurveTokenLiquidityClaimed struct {
	PairId [32]byte
	To     common.Address
	Amount *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterLiquidityClaimed is a free log retrieval operation binding the contract event 0xffc9ea8393d69ab0af7b97fd3c93d4b7960d18d8ed0795313c9f84b087c64eb5.
//
// Solidity: event LiquidityClaimed(bytes32 indexed pairId, address to, uint256 amount)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterLiquidityClaimed(opts *bind.FilterOpts, pairId [][32]byte) (*BondingCurveTokenLiquidityClaimedIterator, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "LiquidityClaimed", pairIdRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenLiquidityClaimedIterator{contract: _BondingCurveToken.contract, event: "LiquidityClaimed", logs: logs, sub: sub}, nil
}

// WatchLiquidityClaimed is a free log subscription operation binding the contract event 0xffc9ea8393d69ab0af7b97fd3c93d4b7960d18d8ed0795313c9f84b087c64eb5.
//
// Solidity: event LiquidityClaimed(bytes32 indexed pairId, address to, uint256 amount)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchLiquidityClaimed(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenLiquidityClaimed, pairId [][32]byte) (event.Subscription, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "LiquidityClaimed", pairIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenLiquidityClaimed)
				if err := _BondingCurveToken.contract.UnpackLog(event, "LiquidityClaimed", log); err != nil {
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

// ParseLiquidityClaimed is a log parse operation binding the contract event 0xffc9ea8393d69ab0af7b97fd3c93d4b7960d18d8ed0795313c9f84b087c64eb5.
//
// Solidity: event LiquidityClaimed(bytes32 indexed pairId, address to, uint256 amount)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseLiquidityClaimed(log types.Log) (*BondingCurveTokenLiquidityClaimed, error) {
	event := new(BondingCurveTokenLiquidityClaimed)
	if err := _BondingCurveToken.contract.UnpackLog(event, "LiquidityClaimed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BondingCurveTokenLiquidityLockedIterator is returned from FilterLiquidityLocked and is used to iterate over the raw logs and unpacked data for LiquidityLocked events raised by the BondingCurveToken contract.
type BondingCurveTokenLiquidityLockedIterator struct {
	Event *BondingCurveTokenLiquidityLocked // Event containing the contract specifics and raw log

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
func (it *BondingCurveTokenLiquidityLockedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenLiquidityLocked)
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
		it.Event = new(BondingCurveTokenLiquidityLocked)
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
func (it *BondingCurveTokenLiquidityLockedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenLiquidityLockedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenLiquidityLocked represents a LiquidityLocked event raised by the BondingCurveToken contract.
type BondingCurveTokenLiquidityLocked struct {
	PairId     [32]byte
	LpToken    common.Address
	Amount     *big.Int
	UnlockTime *big.Int
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterLiquidityLocked is a free log retrieval operation binding the contract event 0xf3fbf2e69a6739560a33eb540b7b6b6890517049fa96bee4d183934710524f77.
//
// Solidity: event LiquidityLocked(bytes32 indexed pairId, address lpToken, uint256 amount, uint256 unlockTime)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterLiquidityLocked(opts *bind.FilterOpts, pairId [][32]byte) (*BondingCurveTokenLiquidityLockedIterator, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "LiquidityLocked", pairIdRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenLiquidityLockedIterator{contract: _BondingCurveToken.contract, event: "LiquidityLocked", logs: logs, sub: sub}, nil
}

// WatchLiquidityLocked is a free log subscription operation binding the contract event 0xf3fbf2e69a6739560a33eb540b7b6b6890517049fa96bee4d183934710524f77.
//
// Solidity: event LiquidityLocked(bytes32 indexed pairId, address lpToken, uint256 amount, uint256 unlockTime)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchLiquidityLocked(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenLiquidityLocked, pairId [][32]byte) (event.Subscription, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "LiquidityLocked", pairIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenLiquidityLocked)
				if err := _BondingCurveToken.contract.UnpackLog(event, "LiquidityLocked", log); err != nil {
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

// ParseLiquidityLocked is a log parse operation binding the contract event 0xf3fbf2e69a6739560a33eb540b7b6b6890517049fa96bee4d183934710524f77.
//
// Solidity: event LiquidityLocked(bytes32 indexed pairId, address lpToken, uint256 amount, uint256 unlockTime)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseLiquidityLocked(log types.Log) (*BondingCurveTokenLiquidityLocked, error) {
	event := new(BondingCurveTokenLiquidityLocked)
	if err := _BondingCurveToken.contract.UnpackLog(event, "LiquidityLocked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BondingCurveTokenMigratedIterator is returned from FilterMigrated and is used to iterate over the raw logs and unpacked data for Migrated events raised by the BondingCurveToken contract.
type BondingCurveTokenMigratedIterator struct {
	Event *BondingCurveTokenMigrated // Event containing the contract specifics and raw log

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
func (it *BondingCurveTokenMigratedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenMigrated)
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
		it.Event = new(BondingCurveTokenMigrated)
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
func (it *BondingCurveTokenMigratedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenMigratedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenMigrated represents a Migrated event raised by the BondingCurveToken contract.
type BondingCurveTokenMigrated struct {
	PairId                [32]byte
	Pool                  common.Address
	LockedLiquidityAmount *big.Int
	Raw                   types.Log // Blockchain specific contextual infos
}

// FilterMigrated is a free log retrieval operation binding the contract event 0x8d598afb033baf391d081d61b5e18836dcd5caf14542f5a4ed0a1a0c2619eb65.
//
// Solidity: event Migrated(bytes32 indexed pairId, address pool, uint256 lockedLiquidityAmount)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterMigrated(opts *bind.FilterOpts, pairId [][32]byte) (*BondingCurveTokenMigratedIterator, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "Migrated", pairIdRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenMigratedIterator{contract: _BondingCurveToken.contract, event: "Migrated", logs: logs, sub: sub}, nil
}

// WatchMigrated is a free log subscription operation binding the contract event 0x8d598afb033baf391d081d61b5e18836dcd5caf14542f5a4ed0a1a0c2619eb65.
//
// Solidity: event Migrated(bytes32 indexed pairId, address pool, uint256 lockedLiquidityAmount)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchMigrated(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenMigrated, pairId [][32]byte) (event.Subscription, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "Migrated", pairIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenMigrated)
				if err := _BondingCurveToken.contract.UnpackLog(event, "Migrated", log); err != nil {
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

// ParseMigrated is a log parse operation binding the contract event 0x8d598afb033baf391d081d61b5e18836dcd5caf14542f5a4ed0a1a0c2619eb65.
//
// Solidity: event Migrated(bytes32 indexed pairId, address pool, uint256 lockedLiquidityAmount)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseMigrated(log types.Log) (*BondingCurveTokenMigrated, error) {
	event := new(BondingCurveTokenMigrated)
	if err := _BondingCurveToken.contract.UnpackLog(event, "Migrated", log); err != nil {
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
	PairId     [32]byte
	BaseToken  common.Address
	OtherToken common.Address
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterPairRegistered is a free log retrieval operation binding the contract event 0x157b5bda8c36b5ae40a6f0d041dce8790309b04707aa024e9a73ee87287372b4.
//
// Solidity: event PairRegistered(bytes32 indexed pairId, address indexed baseToken, address indexed otherToken)
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

// WatchPairRegistered is a free log subscription operation binding the contract event 0x157b5bda8c36b5ae40a6f0d041dce8790309b04707aa024e9a73ee87287372b4.
//
// Solidity: event PairRegistered(bytes32 indexed pairId, address indexed baseToken, address indexed otherToken)
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

// ParsePairRegistered is a log parse operation binding the contract event 0x157b5bda8c36b5ae40a6f0d041dce8790309b04707aa024e9a73ee87287372b4.
//
// Solidity: event PairRegistered(bytes32 indexed pairId, address indexed baseToken, address indexed otherToken)
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

// BondingCurveTokenRefundIssuedIterator is returned from FilterRefundIssued and is used to iterate over the raw logs and unpacked data for RefundIssued events raised by the BondingCurveToken contract.
type BondingCurveTokenRefundIssuedIterator struct {
	Event *BondingCurveTokenRefundIssued // Event containing the contract specifics and raw log

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
func (it *BondingCurveTokenRefundIssuedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenRefundIssued)
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
		it.Event = new(BondingCurveTokenRefundIssued)
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
func (it *BondingCurveTokenRefundIssuedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenRefundIssuedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenRefundIssued represents a RefundIssued event raised by the BondingCurveToken contract.
type BondingCurveTokenRefundIssued struct {
	User   common.Address
	Token  common.Address
	Amount *big.Int
	Reason [32]byte
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterRefundIssued is a free log retrieval operation binding the contract event 0x81f567b107b88cd15945e818a881a630a5a1f4a0d2dfc96862b084dbe4ecdcd0.
//
// Solidity: event RefundIssued(address indexed user, address indexed token, uint256 amount, bytes32 reason)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterRefundIssued(opts *bind.FilterOpts, user []common.Address, token []common.Address) (*BondingCurveTokenRefundIssuedIterator, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var tokenRule []interface{}
	for _, tokenItem := range token {
		tokenRule = append(tokenRule, tokenItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "RefundIssued", userRule, tokenRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenRefundIssuedIterator{contract: _BondingCurveToken.contract, event: "RefundIssued", logs: logs, sub: sub}, nil
}

// WatchRefundIssued is a free log subscription operation binding the contract event 0x81f567b107b88cd15945e818a881a630a5a1f4a0d2dfc96862b084dbe4ecdcd0.
//
// Solidity: event RefundIssued(address indexed user, address indexed token, uint256 amount, bytes32 reason)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchRefundIssued(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenRefundIssued, user []common.Address, token []common.Address) (event.Subscription, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var tokenRule []interface{}
	for _, tokenItem := range token {
		tokenRule = append(tokenRule, tokenItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "RefundIssued", userRule, tokenRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenRefundIssued)
				if err := _BondingCurveToken.contract.UnpackLog(event, "RefundIssued", log); err != nil {
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

// ParseRefundIssued is a log parse operation binding the contract event 0x81f567b107b88cd15945e818a881a630a5a1f4a0d2dfc96862b084dbe4ecdcd0.
//
// Solidity: event RefundIssued(address indexed user, address indexed token, uint256 amount, bytes32 reason)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseRefundIssued(log types.Log) (*BondingCurveTokenRefundIssued, error) {
	event := new(BondingCurveTokenRefundIssued)
	if err := _BondingCurveToken.contract.UnpackLog(event, "RefundIssued", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BondingCurveTokenRouteSelectedIterator is returned from FilterRouteSelected and is used to iterate over the raw logs and unpacked data for RouteSelected events raised by the BondingCurveToken contract.
type BondingCurveTokenRouteSelectedIterator struct {
	Event *BondingCurveTokenRouteSelected // Event containing the contract specifics and raw log

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
func (it *BondingCurveTokenRouteSelectedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenRouteSelected)
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
		it.Event = new(BondingCurveTokenRouteSelected)
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
func (it *BondingCurveTokenRouteSelectedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenRouteSelectedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenRouteSelected represents a RouteSelected event raised by the BondingCurveToken contract.
type BondingCurveTokenRouteSelected struct {
	PairId [32]byte
	Router common.Address
	Path   []common.Address
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterRouteSelected is a free log retrieval operation binding the contract event 0x7e7172c9683c7220e2140a50d1b598c7ac2d963bfd9c6c270f3e6dc10bab6a50.
//
// Solidity: event RouteSelected(bytes32 indexed pairId, address indexed router, address[] path)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterRouteSelected(opts *bind.FilterOpts, pairId [][32]byte, router []common.Address) (*BondingCurveTokenRouteSelectedIterator, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}
	var routerRule []interface{}
	for _, routerItem := range router {
		routerRule = append(routerRule, routerItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "RouteSelected", pairIdRule, routerRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenRouteSelectedIterator{contract: _BondingCurveToken.contract, event: "RouteSelected", logs: logs, sub: sub}, nil
}

// WatchRouteSelected is a free log subscription operation binding the contract event 0x7e7172c9683c7220e2140a50d1b598c7ac2d963bfd9c6c270f3e6dc10bab6a50.
//
// Solidity: event RouteSelected(bytes32 indexed pairId, address indexed router, address[] path)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchRouteSelected(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenRouteSelected, pairId [][32]byte, router []common.Address) (event.Subscription, error) {

	var pairIdRule []interface{}
	for _, pairIdItem := range pairId {
		pairIdRule = append(pairIdRule, pairIdItem)
	}
	var routerRule []interface{}
	for _, routerItem := range router {
		routerRule = append(routerRule, routerItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "RouteSelected", pairIdRule, routerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenRouteSelected)
				if err := _BondingCurveToken.contract.UnpackLog(event, "RouteSelected", log); err != nil {
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

// ParseRouteSelected is a log parse operation binding the contract event 0x7e7172c9683c7220e2140a50d1b598c7ac2d963bfd9c6c270f3e6dc10bab6a50.
//
// Solidity: event RouteSelected(bytes32 indexed pairId, address indexed router, address[] path)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseRouteSelected(log types.Log) (*BondingCurveTokenRouteSelected, error) {
	event := new(BondingCurveTokenRouteSelected)
	if err := _BondingCurveToken.contract.UnpackLog(event, "RouteSelected", log); err != nil {
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

// BondingCurveTokenVerificationCheckedIterator is returned from FilterVerificationChecked and is used to iterate over the raw logs and unpacked data for VerificationChecked events raised by the BondingCurveToken contract.
type BondingCurveTokenVerificationCheckedIterator struct {
	Event *BondingCurveTokenVerificationChecked // Event containing the contract specifics and raw log

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
func (it *BondingCurveTokenVerificationCheckedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BondingCurveTokenVerificationChecked)
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
		it.Event = new(BondingCurveTokenVerificationChecked)
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
func (it *BondingCurveTokenVerificationCheckedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BondingCurveTokenVerificationCheckedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BondingCurveTokenVerificationChecked represents a VerificationChecked event raised by the BondingCurveToken contract.
type BondingCurveTokenVerificationChecked struct {
	User       common.Address
	Passed     bool
	ReasonCode uint8
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterVerificationChecked is a free log retrieval operation binding the contract event 0x39c0c1e934f634b3e5b8294a059a471aa7f6a757273caf95a99a2f4e0870904a.
//
// Solidity: event VerificationChecked(address indexed user, bool passed, uint8 reasonCode)
func (_BondingCurveToken *BondingCurveTokenFilterer) FilterVerificationChecked(opts *bind.FilterOpts, user []common.Address) (*BondingCurveTokenVerificationCheckedIterator, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}

	logs, sub, err := _BondingCurveToken.contract.FilterLogs(opts, "VerificationChecked", userRule)
	if err != nil {
		return nil, err
	}
	return &BondingCurveTokenVerificationCheckedIterator{contract: _BondingCurveToken.contract, event: "VerificationChecked", logs: logs, sub: sub}, nil
}

// WatchVerificationChecked is a free log subscription operation binding the contract event 0x39c0c1e934f634b3e5b8294a059a471aa7f6a757273caf95a99a2f4e0870904a.
//
// Solidity: event VerificationChecked(address indexed user, bool passed, uint8 reasonCode)
func (_BondingCurveToken *BondingCurveTokenFilterer) WatchVerificationChecked(opts *bind.WatchOpts, sink chan<- *BondingCurveTokenVerificationChecked, user []common.Address) (event.Subscription, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}

	logs, sub, err := _BondingCurveToken.contract.WatchLogs(opts, "VerificationChecked", userRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BondingCurveTokenVerificationChecked)
				if err := _BondingCurveToken.contract.UnpackLog(event, "VerificationChecked", log); err != nil {
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

// ParseVerificationChecked is a log parse operation binding the contract event 0x39c0c1e934f634b3e5b8294a059a471aa7f6a757273caf95a99a2f4e0870904a.
//
// Solidity: event VerificationChecked(address indexed user, bool passed, uint8 reasonCode)
func (_BondingCurveToken *BondingCurveTokenFilterer) ParseVerificationChecked(log types.Log) (*BondingCurveTokenVerificationChecked, error) {
	event := new(BondingCurveTokenVerificationChecked)
	if err := _BondingCurveToken.contract.UnpackLog(event, "VerificationChecked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
