// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"time"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/pkg/errors"
)

func (t *trade) Time() time.Time {
	return *t.Timestamp.Time
}

func (t *trade) Marshal(client questdb.LineSender) questdb.At {
	return client.Table("trades").
		Symbol("pair_address", t.PairAddress).
		Symbol("contract_address", t.ContractAddress).
		Symbol("ion_connect_address", t.ContentIONConnectAddress).
		Symbol("trade_type", string(t.Type)).
		Symbol("trader_address", t.TraderAddress).
		Symbol("transaction_hash", t.TransactionHash).
		Int64Column("base_price", int64(t.BasePrice)).
		DecimalColumn("base_amount", t.BaseAmount).
		DecimalColumn("amount", t.Amount)
}

func (t *tokenAnalytics) registerTrade(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogTokenSwapped) error {
	tradeTyp, baseAmount, amount := buyOrSell(ev)
	contractAddress, _ := logEvent.getString("address")
	tradeData := &trade{
		Timestamp:                *tx.BlockTimestamp,
		PairAddress:              hex.EncodeToString(ev.Pair[:]),
		ContractAddress:          contractAddress,
		ContentIONConnectAddress: "TODO",
		BasePrice:                1, // TODO: fetch ice price
		BaseAmount:               baseAmount,
		Amount:                   amount,
		Type:                     tradeTyp,
		TraderAddress:            ev.Address.String(),
		TransactionHash:          tx.TransactionHash,
	}

	err := questdb.Write[*trade](ctx, t.timescaleDB, tradeData)
	return errors.Wrapf(err, "failed to insert trading data into questdb")
}

func buyOrSell(ev *bondingcurve.LogTokenSwapped) (trade tradeType, baseTokenAmount, creatorOrContentTokenAnount questdb.Decimal) {
	input := questdb.NewDecimal(ev.InputAmount)
	output := questdb.NewDecimal(ev.OutputAmount)
	if ev.Direction { // buy
		return tradeTypeBuy, input, output
	} else { // sell
		return tradeTypeSell, output, input
	}
}
