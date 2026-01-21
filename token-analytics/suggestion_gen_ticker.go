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

	var frames []string
	frames = append(frames, data.ContentImages...)
	frames = append(frames, data.ContentVideoFrames...)

	name, ticker, err = t.llmClient.GenerateTokenNameAndTicker(ctx, data.Creator.Name, data.Content, frames)
	if err != nil {
		return "", "", t.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, data.ContentID, err, 1, 1)
	}

	err = t.onSuggestionTickerGenerationSuccess(ctx, data, ticker, name)
	if err != nil {
		return "", "", t.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, data.ContentID, err, 1, 1)
	}

	return name, ticker, nil
}
