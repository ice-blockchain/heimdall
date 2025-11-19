// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"time"
)

type CommunityToken struct {
	Type        string     `json:"type,omitempty"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	ImageURL    string     `json:"imageUrl,omitempty"`
	CreatedAt   time.Time  `json:"createdAt,omitzero"`
	Addresses   Addresses  `json:"addresses,omitzero"`
	Creator     User       `json:"creator,omitzero"`
	MarketData  MarketData `json:"marketData,omitzero"`
}

type Addresses struct {
	Blockchain string `json:"blockchain,omitempty"`
	IonConnect string `json:"ionConnect,omitempty"`
}

type User struct {
	ID               string   `json:"id,omitempty"`
	MasterPubkey     string   `json:"masterPubkey,omitempty"`
	Username         string   `json:"name,omitempty"`
	Display          string   `json:"display,omitempty"`
	Avatar           string   `json:"avatar,omitempty"`
	IonConnect       string   `json:"ionConnect,omitempty"`
	Verified         bool     `json:"verified"`
	IONConnectRelays []string `json:"ionConnectRelays,omitempty"`
}

type MarketData struct {
	Ticker    string   `json:"ticker,omitempty"`
	MarketCap float64  `json:"marketCap"`
	Volume    float64  `json:"volume"`
	PriceUSD  float64  `json:"priceUSD"`
	Holders   uint64   `json:"holders"`
	Position  Position `json:"position,omitzero"`
}

type Position struct {
	Rank          uint64  `json:"rank"`
	Amount        int64   `json:"amount"`
	AmountUSD     float64 `json:"amountUSD"`
	PnL           float64 `json:"pnl"`
	PnLPercentage float64 `json:"pnlPercentage"`
}

type TradePosition struct {
	Holder     User      `json:"holder,omitzero"`
	Addresses  Addresses `json:"addresses,omitzero"`
	CreatedAt  time.Time `json:"createdAt,omitzero"`
	Type       string    `json:"type,omitempty"`
	Amount     int64     `json:"amount"`
	AmountUSD  float64   `json:"amountUSD"`
	Balance    int64     `json:"balance"`
	BalanceUSD float64   `json:"balanceUSD"`
}

type Trade struct {
	Creator  User          `json:"creator,omitzero"`
	Position TradePosition `json:"position,omitzero"`
}

type TradeStatsAggregate struct {
	VolumeUSD           float64 `json:"volumeUSD"`
	NumberOfBuys        uint64  `json:"numberOfBuys"`
	BuysTotalAmountUSD  float64 `json:"buysTotalAmountUSD"`
	NumberOfSells       int64   `json:"numberOfSells"`
	SellsTotalAmountUSD float64 `json:"sellsTotalAmountUSD"`
	NetBuy              float64 `json:"netBuy"`
}

type TradeStats struct {
	Bucket5Min    TradeStatsAggregate `json:"5m,omitzero"`
	Bucket1Hour   TradeStatsAggregate `json:"1h,omitzero"`
	Bucket6Hours  TradeStatsAggregate `json:"6h,omitzero"`
	Bucket24Hours TradeStatsAggregate `json:"24h,omitzero"`
}

type OHLCV struct {
	Timestamp int64   `json:"timestamp"`
	Open      float64 `json:"open"`
	High      float64 `json:"high"`
	Low       float64 `json:"low"`
	Close     float64 `json:"close"`
	Volume    float64 `json:"volume"`
}
