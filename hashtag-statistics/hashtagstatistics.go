// SPDX-License-Identifier: ice License 1.0

package hashtagstatistics

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func New(ctx context.Context) HashtagStatistics {
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)

	return &hashtagStatisticsRepository{
		db:       db,
		shutdown: db.Close,
	}
}

func (h *hashtagStatisticsRepository) Process(ctx context.Context, events []*model.Event) error {
	if len(events) == 0 {
		return nil
	}
	var allHashtags []string
	placeholders := make([]string, 0, len(events))
	args := make([]interface{}, 0, len(events)*3)
	for i, event := range events {
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d, $%d::text[])", i*3+1, i*3+2, i*3+3))
		var address string
		if event.Kind == nostr.KindTextNote {
			address = event.ID
		} else {
			address = strconv.Itoa(event.Kind) + ":" + event.GetMasterPublicKey() + ":" + event.Tags.GetD()
		}
		var contentToSearch string
		if event.Content != "" {
			contentToSearch = event.Content
		} else {
			richTextTag := event.GetTag(model.CustomIONTagRichText)
			if richTextTag != nil && len(richTextTag) >= 3 && richTextTag[2] != "" {
				contentToSearch = richTextTag[2]
			}
		}
		hashtags := extractUniqueHashtags(contentToSearch)
		args = append(args, address, event.GetMasterPublicKey(), hashtags)
		allHashtags = append(allHashtags, hashtags...)
	}
	if len(allHashtags) == 0 {
		return nil
	}

	stmt := fmt.Sprintf(`
		WITH valid_events AS (
			SELECT v.address, v.master_pubkey, v.hashtags
			FROM (VALUES %s) AS v(address, master_pubkey, hashtags)
			JOIN users u ON v.master_pubkey = u.master_pubkey
		),
		inserted_events AS (
			INSERT INTO processed_hashtag_statistics_events (event_address, event_author_master_pubkey, hashtags) 
				SELECT address, master_pubkey, hashtags FROM valid_events
			ON CONFLICT (event_address) DO NOTHING
			RETURNING event_address, hashtags
		)
		INSERT INTO hashtag_statistics (hashtag, occurrences)
			SELECT hashtag, COUNT(event_address)
				FROM inserted_events, unnest(hashtags) AS hashtag
			GROUP BY hashtag
		ON CONFLICT (hashtag) DO UPDATE 
		SET occurrences = hashtag_statistics.occurrences + EXCLUDED.occurrences`, strings.Join(placeholders, ","))

	_, err := storage.Exec(ctx, h.db, stmt, args...)
	if err != nil {
		return errors.Wrap(err, "failed to insert hashtags")
	}

	return nil
}

func (h *hashtagStatisticsRepository) GetTopHashtags(ctx context.Context, limit int) ([]string, error) {
	stmt := `
		SELECT array_agg(x.hashtag) hashtags
		FROM (
			SELECT hashtag
			FROM hashtag_statistics
			ORDER BY occurrences DESC
			LIMIT $1
		) as x;`

	res, err := storage.Select[topHashtags](ctx, h.db, stmt, limit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get top hashtags")
	}
	if res == nil {
		return []string{}, nil
	}

	return res[0].Hashtags, nil
}

func (h *hashtagStatisticsRepository) GetTopHashtagsByKeyword(ctx context.Context, keyword string, limit int) ([]string, error) {
	if !validKeywordChars.MatchString(keyword) {
		return []string{}, nil
	}
	stmt := `
		SELECT array_agg(x.hashtag) hashtags
		FROM (
			SELECT hashtag
			FROM hashtag_statistics
			WHERE lookup @@ to_tsquery($1 || ':*')
			ORDER BY occurrences DESC
			LIMIT $2
		) as x;`
	res, err := storage.Select[topHashtags](ctx, h.db, stmt, keyword, limit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get top hashtags by keyword")
	}
	if res == nil {
		return []string{}, nil
	}

	return res[0].Hashtags, nil
}

func extractUniqueHashtags(content string) []string {
	matches := hashtagRegex.FindAllString(content, -1)
	if len(matches) == 0 {
		return nil
	}
	uniqueHashtags := make(map[string]struct{})
	for _, match := range matches {
		hashtag := strings.ToLower(match[1:])
		uniqueHashtags[hashtag] = struct{}{}
	}
	result := make([]string, 0, len(uniqueHashtags))
	for hashtag := range uniqueHashtags {
		result = append(result, hashtag)
	}

	return result
}

func (i *hashtagStatisticsRepository) Close() error {
	return errors.Wrap(i.shutdown(), "failed to close hashtag statistics repository")
}

func (h *hashtagStatisticsRepository) HealthCheck(ctx context.Context) error {
	if err := h.db.Ping(ctx); err != nil && !storage.IsErr(err, storage.ErrReadOnly) {
		return errors.Wrap(err, "[health-check] hash tags: failed to ping DB")
	}
	return nil
}
