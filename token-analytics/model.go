// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ice-blockchain/wintr/time"
)

type (
	CommunityToken struct {
		Type        string     `json:"type,omitempty"`
		Title       string     `json:"title,omitempty"`
		Description string     `json:"description,omitempty"`
		ImageURL    string     `json:"imageUrl,omitempty"`
		CreatedAt   *time.Time `json:"createdAt,omitempty"`
		Addresses   *Addresses `json:"addresses,omitempty"`
		Creator     User       `json:"creator,omitzero"`
		Launcher    *User      `json:"launcher,omitempty"`
		MarketData  MarketData `json:"marketData,omitzero"`
	}

	Addresses struct {
		Blockchain string `json:"blockchain,omitempty"`
		IonConnect string `json:"ionConnect,omitempty"`
		Twitter    string `json:"twitter,omitempty"`
	}

	User struct {
		MasterPubkey     *string    `json:"-"`
		Username         *string    `json:"name,omitempty"`
		Display          *string    `json:"display,omitempty"`
		Avatar           *string    `json:"avatar,omitempty"`
		Addresses        *Addresses `json:"addresses,omitempty"`
		IONConnectRelays []string   `json:"-"`
		Verified         *bool      `json:"verified,omitempty"`
	}

	MarketData struct {
		Ticker               string                `json:"ticker,omitempty"`
		MarketCap            float64               `json:"marketCap"`
		Supply               string                `json:"supply"`
		Volume               float64               `json:"volume"`
		PriceUSD             float64               `json:"priceUSD"`
		LiquidityUSD         float64               `json:"liquidityUSD"`
		Holders              uint64                `json:"holders"`
		PlatformHolders      uint64                `json:"platformHolders"`
		BondingCurveProgress *BondingCurveProgress `json:"bondingCurveProgress,omitempty"`
		TopPlatformHolders   []HolderPosition      `json:"topPlatformHolders,omitempty"`
		Position             *Position             `json:"position,omitempty"`
	}

	BondingCurveProgress struct {
		CurrentAmount    string  `json:"currentAmount"`
		GoalAmount       string  `json:"goalAmount"`
		RaisedAmount     string  `json:"raisedAmount"`
		CurrentAmountUSD float64 `json:"currentAmountUSD"`
		GoalAmountUSD    float64 `json:"goalAmountUSD"`
		Migrated         bool    `json:"migrated"`
	}

	Position struct {
		Rank          uint64  `json:"rank,omitempty"`
		Amount        string  `json:"amount,omitempty"`
		AmountUSD     float64 `json:"amountUSD,omitempty"`
		PnL           float64 `json:"pnl,omitempty"`
		PnLPercentage float64 `json:"pnlPercentage,omitempty"`
	}

	TradePosition struct {
		CreatedAt  *time.Time `json:"createdAt,omitempty"`
		Addresses  *Addresses `json:"addresses,omitempty"`
		Type       TradeType  `json:"type,omitempty"`
		Holder     User       `json:"holder,omitzero"`
		Amount     string     `json:"amount"`
		AmountUSD  float64    `json:"amountUSD"`
		Balance    string     `json:"balance"`
		BalanceUSD float64    `json:"balanceUSD"`
	}

	Trade struct {
		TokenExternalAddress string        `json:"-" db:"external_address"` // matching with subscriptions
		Creator              User          `json:"creator,omitzero"`
		Position             TradePosition `json:"position,omitempty"`
	}

	TradeStatsAggregate struct {
		AggregationInterval string  `json:"-" db:"aggregation_interval" redis:"-"`
		VolumeUSD           float64 `json:"volumeUSD" db:"volume_usd" redis:"volume_usd"`
		NumberOfBuys        uint64  `json:"numberOfBuys" db:"number_of_buys" redis:"number_of_buys"`
		BuysTotalAmountUSD  float64 `json:"buysTotalAmountUSD" db:"buys_total_amount_usd" redis:"buys_total_amount_usd"`
		NumberOfSells       uint64  `json:"numberOfSells" db:"number_of_sells" redis:"number_of_sells"`
		SellsTotalAmountUSD float64 `json:"sellsTotalAmountUSD" db:"sells_total_amount_usd" redis:"sells_total_amount_usd"`
		NetBuy              float64 `json:"netBuy" redis:"net_buy"`
		PriceDiff           float64 `json:"priceDiff" redis:"price_diff"`
		CurrentPrice        float64 `json:"-" db:"current_price" redis:"-"`
		PriceAgo            float64 `json:"-" db:"price_ago" redis:"-"`
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
		Amount        string  `json:"amount"`
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

	PlatformGroupIonConnect = "ionconnect"
	PlatformGroupXCom       = "xcom"
)

func GetPlatformFromExternalAddress(externalAddress string) Platform {
	if len(externalAddress) < 1 {
		return ""
	}
	return Platform(externalAddress[0:1])
}

// Format: 0:{master}:
func BuildProfileExternalAddress(master string) string {
	return "0:" + master + ":"
}

// Format: {kind}:{master}:{dTag}
func BuildContentExternalAddress(kind int, master, dTag string) string {
	return strconv.Itoa(kind) + ":" + master + ":" + dTag
}

func IsProfileType(tokenType string) bool {
	return tokenType == TokenTypeProfile
}

func IsContentType(tokenType string) bool {
	return tokenType == TokenTypePost || tokenType == TokenTypeVideo || tokenType == TokenTypeArticle
}

func buildAddressesFromExternalAddressAndPlatform(externalAddress, platform string, bnbBscAddress string, ionConnectAddress ...string) (*Addresses, error) {
	ionConnect := ""
	if len(ionConnectAddress) > 0 && ionConnectAddress[0] != "" {
		ionConnect = ionConnectAddress[0]
	}
	if externalAddress == "" && bnbBscAddress == "" {
		return nil, nil
	}
	if platform == "" {
		return nil, fmt.Errorf("platform cannot be empty")
	}

	var addresses Addresses
	switch platform {
	case PlatformGroupIonConnect:
		addresses = Addresses{
			IonConnect: externalAddress,
		}
	case PlatformGroupXCom:
		addresses = Addresses{
			Twitter: externalAddress,
		}
		if bnbBscAddress != "" {
			addresses.Blockchain = bnbBscAddress
		}
		if ionConnect != "" {
			addresses.IonConnect = ionConnect
		}
	default:
		return nil, fmt.Errorf("unknown platform '%s' for external_address: %s", platform, externalAddress)
	}

	return &addresses, nil
}

func buildTokenAddressesFromContractAndExternalAddress(contractAddress, externalAddress, platform string, ionConnectAddress ...string) (*Addresses, error) {
	addresses, err := buildAddressesFromExternalAddressAndPlatform(externalAddress, platform, "", ionConnectAddress...)
	if err != nil {
		return nil, err
	}
	if addresses == nil {
		return nil, nil
	}
	addresses.Blockchain = contractAddress

	return addresses, nil
}

func extractIonConnectFromTokenExternalAddress(tokenExternalAddress, platform string) string {
	if platform != PlatformGroupXCom {
		return ""
	}
	parts := strings.Split(tokenExternalAddress, ":")
	if len(parts) >= 2 {
		return parts[1]
	}

	return ""
}
