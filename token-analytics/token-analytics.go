package tokenanalytics

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-multierror"
	appconfig "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/pkg/errors"
)

func New(ctx context.Context) TokenAnalytics {
	fmt.Println(eventTokenCreated.Hex()) // should match ingested data

	var cfg config
	appconfig.MustLoadFromKey(applicationYamlKey, &cfg)
	db := storage.MustConnect(ctx, sourceDDL, applicationYamlKey)
	targetDB := storagev3.MustConnect(ctx, applicationYamlKey)
	t := &tokenAnalytics{
		ingestedDataDB:  db,
		processedDataDB: targetDB,
		shutdown: func() error {
			return multierror.Append(
				errors.Wrapf(db.Close(), "failed to close source db"),
				errors.Wrapf(targetDB.Close(), "failed to close target db"),
			)
		},
	}
	return t
}

func (t *tokenAnalytics) Close() error {
	// TODO wg to complete routines
	return t.shutdown()
}

func (t *tokenAnalytics) MustStart(ctx context.Context) {
	// start processing routines + wg to complete
}
