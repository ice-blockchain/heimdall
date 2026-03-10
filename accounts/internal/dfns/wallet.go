// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	stdlibtime "time"

	"github.com/pkg/errors"
)

func (c *dfnsClient) ListWallets(ctx context.Context, userID string) ([]Wallet, error) {
	header := http.Header{}
	wallets := make([]Wallet, 0)
	params := struct {
		OwnerID string `form:"ownerId"`
	}{
		OwnerID: userID,
	}
	resp, err := dfnsCall[struct {
		OwnerID string `form:"ownerId"`
	}, page[Wallet]](ctx, c, &params, "GET", "/wallets", header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list wallets for %v", userID)
	}
	nextPageToken := resp.NextPageToken
	wallets = append(wallets, resp.Items...)
	for nextPageToken != nil && *nextPageToken != "" {
		resp, err = dfnsCall[struct {
			OwnerID         string `form:"ownerId"`
			PaginationToken string `form:"paginationToken"`
		}, page[Wallet]](ctx, c, &struct {
			OwnerID         string `form:"ownerId"`
			PaginationToken string `form:"paginationToken"`
		}{
			OwnerID:         userID,
			PaginationToken: *nextPageToken,
		}, "GET", "/wallets/", header)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list wallets for %v (pagination %v)", userID, *nextPageToken)
		}
		wallets = append(wallets, resp.Items...)
		nextPageToken = resp.NextPageToken
	}

	return wallets, nil
}

func (c *dfnsClient) ListAssets(ctx context.Context, walletID string) (*Assets, error) {
	header := http.Header{}
	resp, err := dfnsCall[struct{}, Assets](ctx, c, nil, "GET", fmt.Sprintf("/wallets/%v/assets", walletID), header, []int{http.StatusNotFound})
	if err != nil {
		if delegatedErr := ParseErrAsDfnsInternalErr(err); delegatedErr != nil {
			var delegatedParsedErr *DfnsInternalError
			if errors.As(delegatedErr, &delegatedParsedErr) && delegatedParsedErr.HTTPStatus == http.StatusNotFound &&
				strings.Contains(delegatedParsedErr.Message, "Can't complete the action because account") && strings.Contains(delegatedParsedErr.Message, "doesn't exist") {
				var wallet *Wallet
				wallet, err = c.GetWallet(ctx, walletID)
				if err != nil {
					return nil, errors.Wrap(err, "near network, not existed account yet and failed to get wallet")
				}
				resp = &Assets{
					Assets:   nil,
					Network:  (*wallet)["network"].(string),
					WalletID: walletID,
				}
			}

		}
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list assets on wallet %v", walletID)
		}
	}

	return resp, nil
}

func (c *dfnsClient) ListNFTs(ctx context.Context, walletID string) (*NFTs, error) {
	header := http.Header{}
	resp, err := dfnsCall[struct{}, NFTs](ctx, c, nil, "GET", fmt.Sprintf("/wallets/%v/nfts", walletID), header, []int{http.StatusBadRequest})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list NFTs on wallet %v", walletID)
	}

	return resp, nil
}

func (c *dfnsClient) GetWallet(ctx context.Context, walletID string) (*Wallet, error) {
	header := http.Header{}
	resp, err := dfnsCall[struct{}, Wallet](ctx, c, nil, "GET", fmt.Sprintf("/wallets/%v", walletID), header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get wallet %v", walletID)
	}

	return resp, nil
}

func (c *dfnsClient) CreateWallet(ctx context.Context, network, name string) (*Wallet, error) {
	header := http.Header{}
	header.Add(authDfnsHeader, dfnsAuthHeader(ctx))
	header.Add(userActionDfnsHeader, dfnsUserActionHeader(ctx))
	resp, err := dfnsCall[struct {
		Network string `json:"network"`
		Name    string `json:"name"`
	}, Wallet](ctx, c, &struct {
		Network string `json:"network"`
		Name    string `json:"name"`
	}{Network: network, Name: name}, "POST", "/wallets", header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to creare wallet %v in %v", name, network)
	}

	return resp, nil
}

func (c *dfnsClient) GetWalletHistory(ctx context.Context, walletID, paginationToken string, limit uint64) (*WalletHistory, error) {
	header := http.Header{}
	header.Add(authDfnsHeader, dfnsAuthHeader(ctx))
	resp, err := dfnsCall[struct {
		PaginationToken string `form:"paginationToken,omitempty"`
		Limit           uint64 `form:"limit"`
	}, WalletHistory](ctx, c, &struct {
		PaginationToken string `form:"paginationToken,omitempty"`
		Limit           uint64 `form:"limit"`
	}{
		PaginationToken: paginationToken,
		Limit:           limit,
	}, "GET", fmt.Sprintf("/wallets/%v/history", walletID), header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list NFTs on wallet %v", walletID)
	}

	return resp, nil
}

func (c *dfnsClient) BroadcastTransactionFromWallet(ctx context.Context, walletId string, transactionData *TransactionPayload) (*TransactionResponse, error) {
	header := http.Header{}
	header.Add(authDfnsHeader, dfnsAuthHeader(ctx))
	header.Add(userActionDfnsHeader, dfnsUserActionHeader(ctx))
	resp, err := dfnsCall[TransactionPayload, TransactionResponse](ctx, c, transactionData, "POST", fmt.Sprintf("/wallets/%v/transactions", walletId), header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to send transaction to wallet %v", walletId)
	}

	return resp, nil
}

func (t *TransactionPayload) MarshalJSON() ([]byte, error) {
	if t == nil {
		return []byte("null"), nil
	}
	if t.rawPayload != nil {
		return t.rawPayload, nil
	}
	values := map[string]any{}
	if t.Payload != nil {
		values = t.Payload
	}
	rPayload := reflect.TypeOf(t).Elem()
	rPayloadVal := reflect.Indirect(reflect.ValueOf(t))
	for i := range rPayload.NumField() {
		field := rPayload.Field(i)
		if jsonTag := field.Tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			var opt string
			jsonTag, opt, _ = strings.Cut(jsonTag, ",")
			val := rPayloadVal.FieldByName(field.Name)
			if opt == "omitempty" && isEmptyValue(val) {
				continue
			}
			values[jsonTag] = val.Interface()
		}
	}

	return json.Marshal(values)
}

func isEmptyValue(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return value.Len() == 0
	case reflect.Bool:
		return !value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return value.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return value.IsNil()
	case reflect.Struct:
		return value.IsZero()
	case reflect.Invalid, reflect.Complex64, reflect.Complex128, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return false
	default:
		return value.IsZero()
	}
}

func (t *TransactionPayload) UnmarshalJSON(b []byte) error {
	data := string(b)
	if data == "null" || data == `""` || data == "" {
		return nil
	}
	var m map[string]any
	err := json.Unmarshal(b, &m)
	if err != nil {
		return err
	}
	*t = TransactionPayload{
		Payload: m,
	}
	if ops, ok := m["userOperations"]; ok {
		t.UserOperations, ok = ops.([]UserOperation)
		if !ok {
			uOps := ops.([]any)
			for _, op := range uOps {
				mOp := op.(map[string]any)
				uOp := UserOperation{}
				if to, ok := mOp["to"]; ok {
					uOp.To = to.(string)
				}
				if value, ok := mOp["value"]; ok {
					uOp.Value = value.(string)
				}
				if data, ok := mOp["data"]; ok {
					uOp.Data = data.(string)
				}
				t.UserOperations = append(t.UserOperations, uOp)
			}
		}
	}
	if feeSponsor, ok := m["feeSponsorId"]; ok {
		t.FeeSponsorId = feeSponsor.(string)
	}
	if maxFeePerGas, ok := m["maxFeePerGas"]; ok {
		fee := (maxFeePerGas.(string))
		t.MaxFeePerGas = &fee
	}
	if maxPriorityFeePerGas, ok := m["maxPriorityFeePerGas"]; ok {
		fee := (maxPriorityFeePerGas.(string))
		t.MaxPriorityFeePerGas = &fee
	}
	t.rawPayload = b
	return nil
}

func (c *dfnsClient) GetNetworkFees(ctx context.Context, network string) (*FeeWithPriority, error) {
	type feeParam struct {
		Network string `form:"network"`
	}
	fees, err := dfnsCall[feeParam, FeeWithPriority](ctx, c, &feeParam{Network: network}, "GET", "/networks/fees", http.Header{}, []int{http.StatusBadRequest})
	return fees, err
}

func (wallet Wallet) ID() (id string) {
	if idI, hasId := wallet["id"]; hasId && idI != nil {
		var ok bool
		if id, ok = idI.(string); !ok {
			return ""
		}
	}
	return id
}
func (wallet Wallet) Network() (network string) {
	if networkI, hasNetwork := wallet["network"]; hasNetwork && networkI != nil {
		var ok bool
		if network, ok = networkI.(string); !ok {
			return ""
		}
	}
	return network
}
func (wallet Wallet) Address() string {
	return wallet["address"].(string)
}
func (wallet Wallet) Name() (name string) {
	if nameI, hasName := wallet["name"]; hasName && nameI != nil {
		var ok bool
		if name, ok = nameI.(string); !ok {
			return ""
		}
	}
	return name
}
func (wallet Wallet) PublicKey() (walletPubKey string) {
	if keyI, hasKey := wallet["signingKey"]; hasKey && keyI != nil {
		key := keyI.(map[string]any)
		if pubkey, hasPk := key["publicKey"]; hasPk {
			walletPubKey = pubkey.(string)
		}
	}
	return walletPubKey
}
func (wallet Wallet) CreatedAt() (*stdlibtime.Time, error) {
	var dateCreated string
	if dateCreatedI, hasDateCreated := wallet["dateCreated"]; hasDateCreated && dateCreatedI != nil {
		var ok bool
		if dateCreated, ok = dateCreatedI.(string); !ok {
			return nil, errors.Errorf("invalid dateCreated %v: must be a string but %T", dateCreatedI, dateCreatedI)
		}
	}
	t, err := stdlibtime.Parse(stdlibtime.RFC3339Nano, dateCreated)
	return &t, err
}
