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
	DisplayName      string   `json:"displayName,omitempty"`
	Display          string   `json:"display,omitempty"`
	Avatar           string   `json:"avatar,omitempty"`
	IonConnect       string   `json:"ionConnect,omitempty"`
	Verified         bool     `json:"verified"`
	IONConnectRelays []string `json:"ionConnectRelays,omitempty"`
}

type MarketData struct {
	Ticker    string   `json:"ticker,omitempty"`
	MarketCap int      `json:"marketCap"`
	Volume    int      `json:"volume"`
	Holders   int      `json:"holders"`
	PriceUSD  float64  `json:"priceUSD"`
	Position  Position `json:"position,omitzero"`
}

type Position struct {
	Rank          int     `json:"rank"`
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
