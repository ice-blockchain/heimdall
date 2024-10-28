// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"fmt"
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) CreateWalletView(ctx context.Context, userID, name string, items []*WalletViewItem) (*WalletView, error) {
	now := time.Now()
	params := []any{now, name, userID}
	rowsSql, extraParams := buildInsert(items, 3)
	params = append(params, extraParams...)
	rows, err := storage.Exec(ctx, a.db, fmt.Sprintf(`INSERT INTO wallet_views(created_at, updated_at, name,      user_id, items) 
															VALUES  ($1,         $1,         $2,        $3,     array[%v]    );`, rowsSql),
		params...)
	if err != nil {
		if storage.IsErr(err, storage.ErrRelationNotFound) {
			return nil, ErrNotFound
		}
		return nil, errors.Wrap(err, "failed to create wallet view")
	}
	if rows == 0 {
		return nil, errors.Errorf("failed to create wallet view, unexpected rows count %v", rows)
	}

	return &WalletView{
		Name:      name,
		Items:     items,
		CreatedAt: now,
		UpdatedAt: now,
		UserID:    userID,
	}, nil
}
func (a *accounts) GetWalletViews(ctx context.Context, userID string) ([]*WalletView, error) {
	views, err := storage.Select[WalletView](ctx, a.db, `SELECT 
    created_at, updated_at, name, user_id, array_to_json(items) as items
    FROM wallet_views WHERE user_id = $1`, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get wallet views for user %v", userID)
	}

	return views, nil
}

func (a *accounts) AllSupportedCoins(knownVersion *int) (int, []*AvailableCoin, error) {
	if knownVersion != nil && *knownVersion >= a.cfg.SupportedCoins.Version {
		return a.cfg.SupportedCoins.Version, nil, ErrNotChanged
	}
	res := make([]*AvailableCoin, 0, len(a.cfg.SupportedCoins.SupportedCoins))
	for _, coin := range a.cfg.SupportedCoins.SupportedCoins {
		res = append(res, &AvailableCoin{
			Coin:    coin.Coin,
			Network: coin.Network,
		})
	}

	return a.cfg.SupportedCoins.Version, res, nil
}

func buildInsert(items []*WalletViewItem, nextIndex int) (string, []any) {
	rows := make([]string, 0, len(items))
	params := make([]any, 0, len(items)*2)
	for _, i := range items {
		rows = append(rows, fmt.Sprintf("row($%v,$%v)::wallet_view_item", nextIndex+1, nextIndex+2))
		params = append(params, i.Coin, i.WalletID)
		nextIndex += 2
	}

	return strings.Join(rows, ","), params
}

func (w *WalletViewItems) Scan(value any) error {
	return errors.Wrapf(json.Unmarshal([]byte((value.(string))), w), "failed to unmarshal value from db %v", value)
}

func (a *accounts) DeleteWalletView(ctx context.Context, userID, name string) error {
	row, err := storage.ExecOne[struct {
		Deleted bool `db:"deleted"`
		HasMore bool `db:"has_more"`
	}](ctx, a.db,
		`WITH del AS (
				DELETE FROM wallet_views WHERE user_id = $1 AND name = $2 AND EXISTS(SELECT 1 FROM wallet_views WHERE user_id = $1 AND name != $2) RETURNING name
			)
			SELECT del.name IS NOT NULL AS deleted, (wv.name is not null AND wv.name!=$2) AS has_more  FROM del RIGHT JOIN wallet_views wv 
			ON wv.user_id = $1
			WHERE wv.user_id = $1			
LIMIT 1`, userID, name)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return ErrNotChanged
		}

		return errors.Wrapf(err, "failed to delete wallet view %v for user %v", name, userID)
	}
	if !row.Deleted && row.HasMore {
		return ErrNotChanged
	}
	if !row.Deleted && !row.HasMore {
		return ErrDeleteLast
	}

	return nil
}

func (a *accounts) ModifyWalletView(ctx context.Context, userID, name, newName string, items []*WalletViewItem) (*WalletView, error) {
	now := time.Now()
	params := []any{userID, name, newName, now}
	itemsSQL, extraParams := buildInsert(items, 4)
	params = append(params, extraParams...)
	view, err := storage.ExecOne[WalletView](ctx, a.db, fmt.Sprintf(`UPDATE wallet_views 
	SET 
	    name = $3,
		items = array[%v],
		updated_at = $4
	WHERE user_id = $1 AND name = $2 RETURNING created_at, updated_at, name, user_id, array_to_json(items) as items`, itemsSQL), params...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to modify wallet view %v for user %v", name, userID)
	}

	return view, nil
}
