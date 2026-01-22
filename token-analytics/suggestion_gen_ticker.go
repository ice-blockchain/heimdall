// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
)

func (t *tokenAnalytics) generateTokenSuggestionTicker(ctx context.Context, data *CreationDetailsData) (name, ticker string, err error) {
	err = t.updateTokenSuggestionRecordStatusAndFields(ctx, data.ContentID, TokenDetailsGenerationStatusGenerating, map[string]interface{}{})
	if err != nil {
		return "", "", t.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, data.ContentID, err, 1, 1)
	}

	name, ticker, err = t.llmClient.GenerateTokenNameAndTicker(ctx,
		data.Creator.Name,
		data.Content,
		data.ContentImages,
		data.ContentVideoFrames)
	if err != nil {
		return "", "", t.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, data.ContentID, err, 1, 1)
	}

	err = t.onSuggestionTickerGenerationSuccess(ctx, data, ticker, name)
	if err != nil {
		return "", "", t.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, data.ContentID, err, 1, 1)
	}

	return name, ticker, nil
}
