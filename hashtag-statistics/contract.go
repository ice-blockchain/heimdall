// SPDX-License-Identifier: ice License 1.0

package hashtagstatistics

import (
	"context"
	_ "embed"
	"io"
	"regexp"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

type HashtagStatistics interface {
	io.Closer
	HealthCheck(ctx context.Context) error
	Process(ctx context.Context, events []*model.Event) error
	GetTopHashtags(ctx context.Context, limit int) ([]string, error)
	GetTopHashtagsByKeyword(ctx context.Context, keyword string, limit int) ([]string, error)
}

const (
	applicationYamlKey = "hashtagstatistics"
)

var (
	//go:embed DDL.sql
	ddl string

	hashtagRegex = regexp.MustCompile(`#[a-zA-Z0-9_]+`)
)

type (
	hashtag     = string
	topHashtags struct {
		Hashtags []string `db:"hashtags"`
	}
	hashtagStatisticsRepository struct {
		db       *storage.DB
		shutdown func() error
	}
)
