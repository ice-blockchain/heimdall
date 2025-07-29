// SPDX-License-Identifier: ice License 1.0

package nftcontent

import (
	"context"
	_ "embed"
	"io"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

const (
	NFTContentTypeAccount NFTContentType = "account"
	NFTContentTypePost    NFTContentType = "post"
	NFTContentTypeArticle NFTContentType = "article"
	NFTContentTypeVideo   NFTContentType = "video"

	NFTContentStatusNew       NFTContentStatus = "new"
	NFTContentStatusPending   NFTContentStatus = "pending"
	NFTContentStatusCompleted NFTContentStatus = "completed"
)

type (
	NFTContentStatus = string
	NFTContentType   = string
	NFTContent       interface {
		io.Closer
		HealthCheck(ctx context.Context) error
		Process(ctx context.Context, events []*model.Event) error
	}
)

var (
	ErrForbiddenContent     = errors.New("forbidden content")
	ErrNotFound             = errors.New("not found")
	ErrOnBehalfAccessDenied = model.ErrOnBehalfAccessDenied
)

const (
	applicationYamlKey = "nft-content"
)

var (
	//go:embed DDL.sql
	ddl string
)

type (
	nftContent struct {
		db *storage.DB
	}
)
