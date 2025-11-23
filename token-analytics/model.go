// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
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
		Blockchain string `json:"blockchain,omitempty"`
		IonConnect string `json:"ionConnect,omitempty"`
	}

	User struct {
		MasterPubkey     string   `json:"-"`
		Username         string   `json:"name,omitempty"`
		Display          string   `json:"display,omitempty"`
		Avatar           string   `json:"avatar,omitempty"`
		IonConnect       string   `json:"ionConnect,omitempty"`
		Verified         bool     `json:"verified"`
		IONConnectRelays []string `json:"ionConnectRelays,omitempty"`
	}

	MarketData struct {
		Ticker    string   `json:"ticker,omitempty"`
		MarketCap float64  `json:"marketCap"`
		Volume    float64  `json:"volume"`
		PriceUSD  float64  `json:"priceUSD"`
		Holders   uint64   `json:"holders"`
		Position  Position `json:"position,omitzero"`
	}

	Position struct {
		Rank          uint64  `json:"rank"`
		Amount        int64   `json:"amount"`
		AmountUSD     float64 `json:"amountUSD"`
		PnL           float64 `json:"pnl"`
		PnLPercentage float64 `json:"pnlPercentage"`
	}

	TradePosition struct {
		Holder     User      `json:"holder,omitzero"`
		Addresses  Addresses `json:"addresses,omitzero"`
		CreatedAt  time.Time `json:"createdAt,omitzero"`
		Type       TradeType `json:"type,omitempty"`
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
		Timestamp         uint64  `json:"timestamp" db:"timestamp"`
		IONConnectAddress string  `json:"-" db:"ion_connect_address"`
		Open              float64 `json:"open" db:"open"`
		High              float64 `json:"high" db:"high"`
		Low               float64 `json:"low" db:"low"`
		Close             float64 `json:"close" db:"close"`
		Volume            float64 `json:"volume" db:"volume"`
	}

	HolderPosition struct {
		Holder      User    `json:"holder"`
		Rank        uint64  `json:"rank"`
		Amount      uint64  `json:"amount"`
		AmountUSD   float64 `json:"amountUSD"`
		SupplyShare float64 `json:"supplyShare"`
	}

	TopHolderPosition struct {
		Creator  User           `json:"creator,omitempty"`
		Position HolderPosition `json:"position,omitempty"`
	}
)
