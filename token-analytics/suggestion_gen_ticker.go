// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"

	"github.com/ice-blockchain/wintr/riverqueue"
)

type (
	tokenDetailsGenerationTickerWorkerArgs struct {
		Input *CreationDetailsData
	}
	tokenDetailsGenerationTickerWorker struct {
		riverqueue.WorkerDefaults[tokenDetailsGenerationTickerWorkerArgs]
		TA *tokenAnalytics
	}
	tokenDetailsGenerationTickerJob = riverqueue.Job[tokenDetailsGenerationTickerWorkerArgs]
)

func (tokenDetailsGenerationTickerWorkerArgs) Kind() string {
	return "ta_ai_gen_ticker_worker_args"
}

func (w *tokenDetailsGenerationTickerWorker) Work(ctx context.Context, job *tokenDetailsGenerationTickerJob) (err error) {
	err = w.TA.updateTokenSuggestionRecordStatusAndFields(ctx, job.Args.Input.ContentID, TokenDetailsGenerationStatusGenerating, map[string]interface{}{})
	if err != nil {
		return w.TA.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, job.Args.Input.ContentID, err, job.Attempt, job.MaxAttempts)
	}

	var frames []string
	frames = append(frames, job.Args.Input.ContentImages...)
	frames = append(frames, job.Args.Input.ContentVideoFrames...)

	name, ticker, err := w.TA.llmClient.GenerateTokenNameAndTicker(ctx, job.Args.Input.Creator.Name, job.Args.Input.Content, frames)
	if err != nil {
		return w.TA.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, job.Args.Input.ContentID, err, job.Attempt, job.MaxAttempts)
	}

	err = w.TA.onSuggestionTickerGenerationSuccess(ctx, job.Args.Input, ticker, name)
	if err != nil {
		return w.TA.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, job.Args.Input.ContentID, err, job.Attempt, job.MaxAttempts)
	}

	return nil
}
