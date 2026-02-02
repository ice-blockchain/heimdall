// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"errors"
	"fmt"

	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/riverqueue"
)

type (
	tokenDetailsGenerationPictureWorkerArgs struct {
		Input  *CreationDetailsData
		Ticker string
		Name   string
	}
	tokenDetailsGenerationPictureWorker struct {
		riverqueue.WorkerDefaults[tokenDetailsGenerationPictureWorkerArgs]
		TA *tokenAnalytics
	}
	tokenDetailsGenerationPictureJob = riverqueue.Job[tokenDetailsGenerationPictureWorkerArgs]
)

func (tokenDetailsGenerationPictureWorkerArgs) Kind() string {
	return "ta_ai_gen_picture_worker_args"
}

func (w *tokenDetailsGenerationPictureWorker) Work(ctx context.Context, job *tokenDetailsGenerationPictureJob) (err error) {
	err = w.TA.updateTokenSuggestionRecordStatusAndFields(ctx, job.Args.Input.ContentID, TokenDetailsGenerationStatusGeneratingPicture, map[string]any{})
	if err != nil {
		return errors.Join(err, w.TA.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, job.Args.Input.ContentID, err, job.Attempt, job.MaxAttempts))
	}

	base64Image, err := w.TA.llmClient.GenerateTokenImage(ctx,
		job.Args.Input.Creator.Name,
		job.Args.Input.Content,
		job.Args.Ticker,
		job.Args.Name,
		job.Args.Input.ContentImages,
		job.Args.Input.ContentVideoFrames)
	if err != nil {
		log.Error(err, fmt.Sprintf("failed to generate token image for content ID %v: %v", job.Args.Input.ContentID, err))
		return errors.Join(err, w.TA.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, job.Args.Input.ContentID, err, job.Attempt, job.MaxAttempts))
	}

	err = w.TA.onSuggestionPictureGenerationSuccess(ctx, job.Args.Input.ContentID, base64Image, job.Args.Ticker, job.Args.Name)
	if err != nil {
		return errors.Join(err, w.TA.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, job.Args.Input.ContentID, err, job.Attempt, job.MaxAttempts))
	}

	return nil
}
