// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) onPairRegistered(ctx context.Context, tx *txEvent, ev *bondingcurve.LogPairRegistered) error {
	tokenAddress := strings.ToLower(ev.OtherToken.Hex())
	baseTokenAddress := strings.ToLower(ev.BaseToken.Hex())

	log.Debug(fmt.Sprintf("Pair registered: token=%v, baseToken=%v, tx:%v",
		tokenAddress, baseTokenAddress, tx.TransactionHash))

	_, err := storage.Exec(ctx, t.ingestedDataDB, `
		UPDATE tokens
		SET base_token = $1, updated_at = $2
		WHERE contract_address = $3
	`, baseTokenAddress, tx.BlockTimestamp, tokenAddress)

	if err != nil {
		return fmt.Errorf("failed to update base_token for %v: %w", tokenAddress, err)
	}

	log.Debug(fmt.Sprintf("Successfully updated base_token=%v for token %v",
		baseTokenAddress, tokenAddress))

	return nil
}
