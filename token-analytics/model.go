// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"fmt"
	"strconv"
	"time"
)

type (
	CommunityToken struct {
		Type        string     `json:"type,omitempty"`
		Title       string     `json:"title,omitempty"`
		Description string     `json:"description,omitempty"`
		ImageURL    string     `json:"imageUrl,omitempty"`
		CreatedAt   time.Time  `json:"createdAt,omitzero"`
		Addresses   Addresses  `json:"addresses,omitzero"`
		Creator     User       `json:"creator,omitzero"`
		MarketData  MarketData `json:"marketData,omitzero"`
	}

	Addresses struct {
		IonConnect string `json:"ionConnect,omitempty"`
		Twitter    string `json:"twitter,omitempty"`
	}

	User struct {
		MasterPubkey     string    `json:"-"`
		Username         string    `json:"name,omitempty"`
		Display          string    `json:"display,omitempty"`
		Avatar           string    `json:"avatar,omitempty"`
		Addresses        Addresses `json:"addresses,omitempty"`
		IONConnectRelays []string  `json:"-"`
		Verified         bool      `json:"verified"`
	}

	MarketData struct {
		Ticker               string                `json:"ticker,omitempty"`
		MarketCap            float64               `json:"marketCap"`
		Volume               float64               `json:"volume"`
		PriceUSD             float64               `json:"priceUSD"`
		Holders              uint64                `json:"holders"`
		PlatformHolders      uint64                `json:"platformHolders"`
		BondingCurveProgress *BondingCurveProgress `json:"bondingCurveProgress,omitempty"`
		TopPlatformHolders   []HolderPosition      `json:"topPlatformHolders,omitempty"`
		Position             Position              `json:"position,omitempty"`
	}

	BondingCurveProgress struct {
		CurrentAmount    uint64  `json:"currentAmount"`
		GoalAmount       uint64  `json:"goalAmount"`
		CurrentAmountUSD float64 `json:"currentAmountUSD"`
		GoalAmountUSD    float64 `json:"goalAmountUSD"`
	}

	Position struct {
		Rank          uint64  `json:"rank"`
		Amount        uint64  `json:"amount"`
		AmountUSD     float64 `json:"amountUSD"`
		PnL           float64 `json:"pnl"`
		PnLPercentage float64 `json:"pnlPercentage"`
	}

	TradePosition struct {
		CreatedAt  time.Time `json:"createdAt,omitzero"`
		Addresses  Addresses `json:"addresses,omitzero"`
		Type       TradeType `json:"type,omitempty"`
		Holder     User      `json:"holder,omitzero"`
		Amount     uint64    `json:"amount"`
		AmountUSD  float64   `json:"amountUSD"`
		Balance    uint64    `json:"balance"`
		BalanceUSD float64   `json:"balanceUSD"`
	}

	Trade struct {
		Creator  User          `json:"creator,omitzero"`
		Position TradePosition `json:"position,omitzero"`
	}

	TradeStatsAggregate struct {
		AggregationInterval string  `json:"-" db:"aggregation_interval" redis:"-"`
		VolumeUSD           float64 `json:"volumeUSD" db:"volume_usd" redis:"volume_usd"`
		NumberOfBuys        uint64  `json:"numberOfBuys" db:"number_of_buys" redis:"number_of_buys"`
		BuysTotalAmountUSD  float64 `json:"buysTotalAmountUSD" db:"buys_total_amount_usd" redis:"buys_total_amount_usd"`
		NumberOfSells       uint64  `json:"numberOfSells" db:"number_of_sells" redis:"number_of_sells"`
		SellsTotalAmountUSD float64 `json:"sellsTotalAmountUSD" db:"sells_total_amount_usd" redis:"sells_total_amount_usd"`
		NetBuy              float64 `json:"netBuy" redis:"net_buy"`
	}

	TradeStats struct {
		Bucket5Min    *TradeStatsAggregate `json:"5m,omitzero"`
		Bucket1Hour   *TradeStatsAggregate `json:"1h,omitzero"`
		Bucket6Hours  *TradeStatsAggregate `json:"6h,omitzero"`
		Bucket24Hours *TradeStatsAggregate `json:"24h,omitzero"`
	}

	OHLCV struct {
		ExternalAddress string  `json:"-" db:"external_address"`
		Timestamp       uint64  `json:"timestamp" db:"timestamp"`
		Open            float64 `json:"open" db:"open"`
		High            float64 `json:"high" db:"high"`
		Low             float64 `json:"low" db:"low"`
		Close           float64 `json:"close" db:"close"`
		Volume          float64 `json:"volume" db:"volume"`
	}

	HolderPosition struct {
		Holder        User    `json:"holder"`
		Rank          uint64  `json:"rank"`
		Amount        uint64  `json:"amount"`
		AmountUSD     float64 `json:"amountUSD"`
		SupplyShare   float64 `json:"supplyShare,omitempty"`
		PnL           float64 `json:"pnl,omitempty"`
		PnLPercentage float64 `json:"pnlPercentage,omitempty"`
	}

	TopHolderPosition struct {
		Creator  User           `json:"creator,omitempty"`
		Position HolderPosition `json:"position,omitempty"`
	}

	Platform string
)

const (
	PlatformIonConnectProfile Platform = "a" // 0x01
	PlatformIonConnectPost    Platform = "b" // 0x02
	PlatformIonConnectVideo   Platform = "c" // 0x04
	PlatformIonConnectArticle Platform = "d" // 0x08

	PlatformXComArticle Platform = "w" // 0x10
	PlatformXComVideo   Platform = "x" // 0x20
	PlatformXComPost    Platform = "y" // 0x40
	PlatformXComProfile Platform = "z" // 0x80
)

func GetPlatformFromExternalAddress(externalAddress string) Platform {
	if len(externalAddress) < 1 {
		return ""
	}
	return Platform(externalAddress[0:1])
}

// Format: a0:{master}:
func BuildProfileExternalAddress(master string) string {
	return string(PlatformIonConnectProfile) + "0:" + master + ":"
}

// Format: {platformPrefix}{kind}:{master}:{dTag}
func BuildContentExternalAddress(platform Platform, kind int, master, dTag string) string {
	return string(platform) + strconv.Itoa(kind) + ":" + master + ":" + dTag
}

func IsProfileType(externalAddress string) bool {
	if len(externalAddress) < 1 {
		return false
	}
	platform := GetPlatformFromExternalAddress(externalAddress)

	return platform == PlatformIonConnectProfile || platform == PlatformXComProfile
}

func IsContentType(externalAddress string) bool {
	if len(externalAddress) < 1 {
		return false
	}
	platform := GetPlatformFromExternalAddress(externalAddress)
	return platform == PlatformIonConnectPost ||
		platform == PlatformIonConnectVideo ||
		platform == PlatformIonConnectArticle ||
		platform == PlatformXComArticle ||
		platform == PlatformXComVideo ||
		platform == PlatformXComPost
}

func buildAddressesFromExternalAddress(externalAddress string) (Addresses, error) {
	if externalAddress == "" || len(externalAddress) < 1 {
		return Addresses{}, fmt.Errorf("external_address cannot be empty")
	}
	prefix := externalAddress[0:1]

	if prefix == string(PlatformXComProfile) ||
		prefix == string(PlatformXComPost) ||
		prefix == string(PlatformXComVideo) ||
		prefix == string(PlatformXComArticle) {
		return Addresses{
			Twitter: externalAddress[1:],
		}, nil
	}

	if prefix == string(PlatformIonConnectProfile) ||
		prefix == string(PlatformIonConnectPost) ||
		prefix == string(PlatformIonConnectVideo) ||
		prefix == string(PlatformIonConnectArticle) {
		return Addresses{
			IonConnect: externalAddress[1:],
		}, nil
	}

	return Addresses{}, fmt.Errorf("unknown platform prefix '%s' in external_address: %s", prefix, externalAddress)
}
