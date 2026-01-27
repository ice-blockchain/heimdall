// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/guregu/null/v6"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/cdn"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/llm"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

type (
	tokensSuggestionsRecord struct {
		ContentID       string      `db:"content_id"`
		Ticker          null.String `db:"ticker"`
		Name            null.String `db:"name"`
		PictureURL      null.String `db:"picture_url"`
		PictureB64      null.String `db:"picture_b64"`
		Status          string      `db:"status"`
		LastError       null.String `db:"last_error"`
		AttemptCount    int         `db:"attempt_count"`
		CreatedAt       time.Time   `db:"created_at"`
		UpdatedAt       time.Time   `db:"updated_at"`
		CompletedAt     null.Time   `db:"completed_at"`
		LastAttemptedAt null.Time   `db:"last_attempted_at"`
	}
	TokenDetailsGenerationStatus string
)

const (
	TokenDetailsGenerationStatusPending           TokenDetailsGenerationStatus = "pending"
	TokenDetailsGenerationStatusGenerating        TokenDetailsGenerationStatus = "generating_ticker"
	TokenDetailsGenerationStatusGeneratingPicture TokenDetailsGenerationStatus = "generating_picture"
	TokenDetailsGenerationStatusUploading         TokenDetailsGenerationStatus = "uploading"
	TokenDetailsGenerationStatusCompleted         TokenDetailsGenerationStatus = "completed"
	TokenDetailsGenerationStatusFailed            TokenDetailsGenerationStatus = "failed"
)

func ValidateWebpImage(b64image string) error {
	return llm.ValidateWebpImage(b64image)
}

func (t *tokenAnalytics) GenerateTokenSuggestion(ctx context.Context, data *CreationDetailsData) (*SuggestedCreationDetails, error) {
	data.ContentID = strings.ToLower(strings.TrimSpace(data.ContentID))

	record, err := t.FetchSuggestionRecordByContentID(ctx, data.ContentID)
	if err != nil {
		return nil, err
	}

	// Only return existing record if it's in a terminal state (completed or failed)
	// For in-progress states, fall through to re-enqueue or return pending status.
	if record != nil && (TokenDetailsGenerationStatus(record.Status) == TokenDetailsGenerationStatusCompleted ||
		TokenDetailsGenerationStatus(record.Status) == TokenDetailsGenerationStatusFailed) {
		return &SuggestedCreationDetails{
			Ticker:  record.Ticker.String,
			Name:    record.Name.String,
			Picture: record.PictureURL.String,
			Status:  TokenDetailsGenerationStatus(record.Status),
		}, nil
	}

	shouldEnqueue, err := t.TryInsertSuggestionRecord(ctx, data)
	if err != nil {
		return nil, err
	} else if !shouldEnqueue {
		return &SuggestedCreationDetails{Status: TokenDetailsGenerationStatusPending}, nil
	}

	name, ticker, err := t.generateTokenSuggestionTicker(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to enqueue token suggestion generation job for content ID %v: %w", data.ContentID, err)
	}

	return &SuggestedCreationDetails{
		Status: TokenDetailsGenerationStatusGeneratingPicture,
		Ticker: ticker,
		Name:   name,
	}, nil
}

func (t *tokenAnalytics) TryInsertSuggestionRecord(ctx context.Context, data *CreationDetailsData) (bool, error) {
	const stmt = `
	insert into user_tokens_suggestions(content_id, status)
	values ($1, $2)
	ON CONFLICT (content_id) DO UPDATE
	SET
		status            = EXCLUDED.status,
		updated_at        = NOW(),
		completed_at      = NULL,
		last_attempted_at = NULL,
		last_error        = NULL
	WHERE
			(user_tokens_suggestions.status = 'failed'
			AND user_tokens_suggestions.completed_at is not NULL
			AND user_tokens_suggestions.completed_at < NOW() - INTERVAL '3 hours')
		OR
			(user_tokens_suggestions.status = 'pending'
			AND user_tokens_suggestions.completed_at is NULL
			AND user_tokens_suggestions.last_attempted_at is NULL
			AND user_tokens_suggestions.updated_at < NOW() - INTERVAL '10 minutes')
	RETURNING content_id
	`

	val, err := storage.ExecOne[string](ctx, t.ingestedDataDB, stmt, data.ContentID, TokenDetailsGenerationStatusPending)
	if err != nil {
		return false, fmt.Errorf("failed to insert token suggestion record %v: %w", data.ContentID, err)
	}

	return val != nil && *val == data.ContentID, nil
}

func (t *tokenAnalytics) FetchSuggestionRecordByContentID(ctx context.Context, contentID string) (*tokensSuggestionsRecord, error) {
	const stmt = `
	select
		content_id,
		ticker,
		name,
		picture_url,
		status,
		last_error,
		attempt_count,
		created_at,
		updated_at,
		completed_at,
		last_attempted_at
	from
		user_tokens_suggestions
	where
		content_id = $1
	`
	data, err := storage.Get[tokensSuggestionsRecord](ctx, t.ingestedDataDB, stmt, contentID)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch token suggestion record %v: %w", contentID, err)
	}

	return data, nil
}

func (t *tokenAnalytics) OnUploadCompleted(ctx context.Context, fileName, downloadURL string, m *cdn.Metadata) {
	contentID, ok := m.Map["content_id"]
	if !ok {
		log.Warn(fmt.Sprintf("missing content_id in metadata for uploaded file %v", fileName))
		return
	}

	err := t.updateTokenSuggestionRecordStatusAndFields(ctx, contentID, TokenDetailsGenerationStatusCompleted, map[string]any{
		"picture_url":  downloadURL,
		"last_error":   null.String{},
		"completed_at": time.Now(),
	})
	if err != nil {
		log.Error(fmt.Errorf("failed to update completion status for content ID %v: %w", contentID, err))
	}
}

func (t *tokenAnalytics) OnUploadError(ctx context.Context, fileName string, err error, attempt, maxAttempts int, m *cdn.Metadata) {
	contentID, ok := m.Map["content_id"]
	if !ok {
		log.Warn(fmt.Sprintf("missing content_id in metadata for uploaded file %v", fileName))
		return
	}

	updateErr := t.markTokenSuggestionRecordAsFailedOrUpdateError(ctx, contentID, err, attempt, maxAttempts)
	if updateErr != nil {
		log.Error(fmt.Errorf("failed to update error status for content ID %v: %w", contentID, updateErr))
	}
}

func (t *tokenAnalytics) updateTokenSuggestionRecord(ctx context.Context, contentID string, updates map[string]any) error {
	setClauses := []string{"updated_at = NOW()"}
	args := []any{contentID}
	argIndex := 2 // $1 is contentID, $2+ for update values.

	for key, val := range updates {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", key, argIndex))
		args = append(args, val)
		argIndex++
	}

	setClause := strings.Join(setClauses, ", ")
	stmt := fmt.Sprintf(`
		update user_tokens_suggestions
		set %s
		where content_id = $1
	`, setClause)

	_, err := storage.Exec(ctx, t.ingestedDataDB, stmt, args...)
	if err != nil {
		return fmt.Errorf("failed to update token suggestion record %v: %w", contentID, err)
	}
	return nil
}

func (t *tokenAnalytics) markTokenSuggestionRecordAsFailedOrUpdateError(ctx context.Context, contentID string, lastErr error, attempt, maxAttempts int) error {
	updates := map[string]any{
		"last_error": lastErr.Error(),
	}

	if attempt >= maxAttempts {
		updates["status"] = TokenDetailsGenerationStatusFailed
		updates["completed_at"] = time.Now()
	} else {
		updates["last_attempted_at"] = time.Now()
	}

	return t.updateTokenSuggestionRecord(ctx, contentID, updates)
}

func (t *tokenAnalytics) updateTokenSuggestionRecordStatusAndFields(ctx context.Context, contentID string, status TokenDetailsGenerationStatus, fields map[string]any) error {
	if fields == nil {
		fields = make(map[string]any)
	}
	fields["status"] = string(status)
	return t.updateTokenSuggestionRecord(ctx, contentID, fields)
}

func (t *tokenAnalytics) onSuggestionTickerGenerationSuccess(ctx context.Context, data *CreationDetailsData, ticker, name string) error {
	fields := map[string]any{
		"ticker": ticker,
		"name":   name,
	}
	err := t.updateTokenSuggestionRecordStatusAndFields(ctx, data.ContentID, TokenDetailsGenerationStatusGeneratingPicture, fields)
	if err != nil {
		return err
	}

	err = t.riverClient.Push(ctx, &tokenDetailsGenerationPictureWorkerArgs{
		Input:  data,
		Ticker: ticker,
		Name:   name,
	})
	if err != nil {
		return fmt.Errorf("failed to enqueue picture generation job for content ID %v: %w", data.ContentID, err)
	}

	return nil
}

func (t *tokenAnalytics) onSuggestionPictureGenerationSuccess(ctx context.Context, contentID, pictureB64, ticker, name string) error {
	fields := map[string]any{
		"picture_b64": pictureB64,
	}
	err := t.updateTokenSuggestionRecordStatusAndFields(ctx, contentID, TokenDetailsGenerationStatusUploading, fields)
	if err != nil {
		return err
	}

	pictureData, err := base64.StdEncoding.DecodeString(pictureB64)
	if err != nil {
		return fmt.Errorf("failed to decode base64 picture for content ID %v: %w", contentID, err)
	}

	filename := "ts_" + contentID + ".png"
	err = t.cdnClient.SubmitFileUploadJob(ctx, pictureData, "image/png", filename, &cdn.Metadata{
		Map: map[string]string{
			"content_id": contentID,
			"ticker":     ticker,
			"name":       name,
		},
	})
	if err != nil {
		log.Warn(fmt.Sprintf("failed to initiate CDN upload for content ID %v: %v", contentID, err))
		return err
	}

	return nil
}
