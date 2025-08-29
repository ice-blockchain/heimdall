// SPDX-License-Identifier: ice License 1.0

package following

import (
	"context"
	_ "embed"
	"io"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

var (
	ErrOnBehalfAccessDenied = model.ErrOnBehalfAccessDenied
	ErrRelationNotFound     = errors.New("relation not found")
)

type (
	Following interface {
		io.Closer
		HealthCheck(ctx context.Context) error
		ProcessFollowersEvent(ctx context.Context, followListEvent, attestationEvent *model.Event) error
	}
	Config struct{}
)

const (
	applicationYamlKey = "following"
)

var (
	//go:embed DDL.sql
	ddl string
)

type (
	following struct {
		db     *storage.DB
		config *Config
	}
)
