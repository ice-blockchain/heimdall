// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"time"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
)

func (t *trade) Time() time.Time {
	return *t.Timestamp.Time
}

func (t *trade) Marshal(client questdb.LineSender) questdb.At {
	return client.Table("trades").
		Symbol("pair_address", t.PairAddress).
		Symbol("contract_address", t.ContractAddress).
		Symbol("content_ion_connect_address", t.ContentIONConnectAddress).
		Int64Column("price", int64(t.Price)).
		Long256Column("amount", t.Amount).
		Symbol("trade_type", string(t.Type)).
		Symbol("trader_address", t.TraderAddress).
		Symbol("transaction_hash", t.TransactionHash)
}

func (t *tokenAnalytics) registerTrade(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogTokenSwapped) error {
	return nil
}
