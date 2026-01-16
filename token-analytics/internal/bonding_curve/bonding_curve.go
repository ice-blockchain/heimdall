// SPDX-License-Identifier: ice License 1.0

package bondingcurve

import (
	"context"
	_ "embed"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"golang.org/x/sync/singleflight"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

func init() {
	var err error
	ABI, err = abi.JSON(strings.NewReader(ABIJSON))
	log.Panic(errors.Wrapf(err, "failed to parse bonding curve abi"))

	UniswapABI, err = abi.JSON(strings.NewReader(UniswapABIJSON))
	log.Panic(errors.Wrapf(err, "failed to parse uniswap factory abi"))

	UniswapMigratorABI, err = abi.JSON(strings.NewReader(UniswapMigratorABIJSON))
	log.Panic(errors.Wrapf(err, "failed to parse uniswap migrator abi"))

	UniswapPoolABI, err = abi.JSON(strings.NewReader(UniswapPoolABIJSON))
	log.Panic(errors.Wrapf(err, "failed to parse uniswap pool abi"))

	CustomHandleOpsABI, err = abi.JSON(strings.NewReader(CustomHandleOpsABIJSON))
	log.Panic(errors.Wrapf(err, "failed to parse custom handle ops abi"))

	abi4Param, err = abi.JSON(strings.NewReader(swap4ParamABIJSON))
	log.Panic(errors.Wrapf(err, "failed to parse 4-param swap ABI"))
}

func New(ctx context.Context, applicationYamlKey string) BondingCurve {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	b := &bondingCurve{
		cfg:                  cfg,
		pricingSingleflight:  new(singleflight.Group),
		progressSingleflight: new(singleflight.Group),
		priceCache:           ttlcache.New[string, *big.Int](ttlcache.WithTTL[string, *big.Int](cfg.BondingCurve.BondingCurveProgressUpdateFrequency)),
		progressCache:        ttlcache.New[string, *BondingCurveProgress](ttlcache.WithTTL[string, *BondingCurveProgress](cfg.BondingCurve.BondingCurveProgressUpdateFrequency)),
	}
	b.rpcClients = make([]*ethclient.Client, len(cfg.BondingCurve.RPCEndpoints), len(cfg.BondingCurve.RPCEndpoints))
	b.contractClients = make([]*BondingCurveTokenCaller, len(cfg.BondingCurve.RPCEndpoints), len(cfg.BondingCurve.RPCEndpoints))
	contractAddr := common.HexToAddress(cfg.BondingCurve.SmartContractAddress)
	for i, rpcAddr := range cfg.BondingCurve.RPCEndpoints {
		var err error
		connCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		b.rpcClients[i], err = ethclient.DialContext(connCtx, rpcAddr)
		cancel()
		if err != nil {
			log.Panic(errors.Wrapf(err, "failed to establish connection with eth rpc %v (%v)", rpcAddr, i))
		}
		b.contractClients[i], err = NewBondingCurveTokenCaller(contractAddr, b.rpcClients[i])
		if err != nil {
			log.Panic(errors.Wrapf(err, "failed to init bonding curve contract caller with %v (%v)", rpcAddr, i))
		}
	}
	if len(b.contractClients) == 0 {
		log.Panic(errors.New("no rpc endpoints provided for bonding curve"))
	}
	go b.priceCache.Start()
	go func() {
		<-ctx.Done()
		b.priceCache.Stop()
	}()
	return b
}

func (b *bondingCurve) Pricing(ctx context.Context, baseToken common.Address, targetToken []byte, amount *big.Int, sale bool) (price *big.Int, err error) {
	token := targetToken
	if sale {
		token = baseToken.Bytes()
	}
	key := fmt.Sprintf("%X_%v_%v", token, sale, amount.String())
	priceForToken := b.priceCache.Get(key)
	if priceForToken != nil && priceForToken.Value() != nil {
		return priceForToken.Value(), nil
	}
	res, err, _ := b.pricingSingleflight.Do(key, func() (any, error) {
		log.Debug(fmt.Sprintf("Getting pricing for tokens %X %v", targetToken, baseToken.Hex()))
		err = b.retry(ctx, func() error {
			price, err = b.pricing(ctx, baseToken, targetToken, amount, sale)
			return err
		})
		return price, errors.Wrapf(err, "failed to get pricing for token %X", targetToken)
	})

	b.priceCache.Set(key, res.(*big.Int), b.cfg.BondingCurve.BondingCurveProgressUpdateFrequency)
	return res.(*big.Int), err
}

func (b *bondingCurve) pricing(ctx context.Context, baseToken common.Address, targetToken []byte, amount *big.Int, sale bool) (*big.Int, error) {
	client := b.contractClients[atomic.AddUint64(&b.clientLBIndex, 1)%uint64(len(b.contractClients))]
	opts := &bind.CallOpts{Pending: true, Context: ctx}
	if sale {
		return client.QuoteSellOut(opts, targetToken, baseToken.Bytes(), amount)
	}
	return client.QuoteBuyOut(opts, baseToken.Bytes(), targetToken, amount)
}

func (b *bondingCurve) Progress(ctx context.Context, pairId common.Hash) (p *BondingCurveProgress, err error) {
	progressForPair := b.progressCache.Get(pairId.Hex())
	if progressForPair != nil && progressForPair.Value() != nil {
		return progressForPair.Value(), nil
	}
	res, err, _ := b.progressSingleflight.Do(pairId.Hex(), func() (any, error) {
		log.Debug(fmt.Sprintf("Getting progress for pairId %v", pairId.Hex()))
		err = b.retry(ctx, func() error {
			p, err = b.progress(ctx, pairId)
			return err
		})
		return p, err
	})
	b.progressCache.Set(pairId.Hex(), res.(*BondingCurveProgress), b.cfg.BondingCurve.BondingCurveProgressUpdateFrequency)
	return res.(*BondingCurveProgress), err
}

func (b *bondingCurve) progress(ctx context.Context, pairId common.Hash) (*BondingCurveProgress, error) {
	client := b.contractClients[atomic.AddUint64(&b.clientLBIndex, 1)%uint64(len(b.contractClients))]
	var pairIdBytes [32]byte
	copy(pairIdBytes[:], pairId.Bytes())
	opts := &bind.CallOpts{Pending: true, Context: ctx}
	info, err := client.BondingProgress(opts, pairIdBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get progress from bonding curve %v", b.cfg.BondingCurve.SmartContractAddress)
	}

	liquidity, err := client.GetLiquidity(opts, pairIdBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get liquidity from bonding curve %v", b.cfg.BondingCurve.SmartContractAddress)
	}
	return &BondingCurveProgress{
		BondingCurveBondingInfo: &info,
		Liquidity:               liquidity,
	}, nil
}

func (b *bondingCurve) retry(ctx context.Context, fn func() error) (err error) {
	err = backoff.RetryNotify(
		func() error {
			return fn()
		},
		backoff.WithContext(&backoff.ExponentialBackOff{
			InitialInterval:     500 * time.Millisecond,
			RandomizationFactor: 0.5,
			Multiplier:          2.5,
			MaxInterval:         3 * time.Second,
			MaxElapsedTime:      25 * time.Second,
			Stop:                backoff.Stop,
			Clock:               backoff.SystemClock,
		}, ctx),
		func(e error, next time.Duration) {
			log.Info(fmt.Sprintf("failed to call bonding curve %v: %v, retrying in %v... ", b.cfg.BondingCurve.SmartContractAddress, e, next))
		})

	return err
}
