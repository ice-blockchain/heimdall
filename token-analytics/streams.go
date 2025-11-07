package tokenanalytics

import (
	"context"

	"github.com/hashicorp/go-multierror"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/pkg/errors"
)

func (t *tokenAnalytics) createStreamForContractAddress(ctx context.Context, contractAddress string) error {
	_, err := storage.Exec(ctx, t.ingestedDataDB, `INSERT INTO streams(contract_address) VALUES ($1);`, contractAddress)
	if err != nil {
		if storage.IsErr(err, storage.ErrDuplicate) {
			return nil
		}
		return errors.Wrapf(err, "failed to check stream duplicate")
	}
	stream, err := t.quickNode.CreateStream(ctx, contractAddress, contractAddress)
	if err != nil {
		_, rollbackErr := storage.Exec(ctx, t.ingestedDataDB, `DELETE FROM streams WHERE contract_address = $1;`, contractAddress)
		return errors.Wrapf(multierror.Append(err, rollbackErr).ErrorOrNil(), "failed to create stream on qn for %v", contractAddress)
	}
	_, err = storage.Exec(ctx, t.ingestedDataDB, `
			UPDATE streams SET
			    stream_id = $2,
			    created_at = $3,
			    name = $4
			WHERE contract_address = $1;`, contractAddress, stream.ID, stream.CreatedAt, stream.Name)
	return errors.Wrapf(err, "failed to update stream data for %v", contractAddress)
}
