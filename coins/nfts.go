// SPDX-License-Identifier: ice License 1.0

package coins

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/ice-blockchain/heimdall/coins/internal/coingecko"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func (c *coinsRepository) ImportNFTs(ctx context.Context, network string, NFTsInWallet []WalletNFT) (nfts []*NFT, err error) {
	addresses := make([]string, 0, len(NFTsInWallet))
	for _, n := range NFTsInWallet {
		addresses = append(addresses, n["contract"].(string))
	}
	nftCollections, missing, err := c.getNFTCollections(ctx, network, addresses)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get local nfts")
	}
	if len(missing) == 0 {
		return c.populateNFTsWithCollectionInfo(NFTsInWallet, nftCollections), nil
	}
	nftsToImport := make([]WalletNFT, 0, len(missing))
	for _, n := range NFTsInWallet {
		if slices.Contains(missing, n["contract"].(string)) {
			nftsToImport = append(nftsToImport, n)
		}
	}
	imported, err := c.importNFTCollections(ctx, network, nftsToImport, missing)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to import missing NFTs %v %+v", network, missing)
	}
	for k, v := range imported {
		nftCollections[k] = v
	}

	return c.populateNFTsWithCollectionInfo(NFTsInWallet, nftCollections), nil
}

func (c *coinsRepository) populateNFTsWithCollectionInfo(NFTsInWallet []WalletNFT, nftCollections map[string]*NFT) []*NFT {
	res := make([]*NFT, 0, len(NFTsInWallet))
	for _, wn := range NFTsInWallet {
		contractAddress := wn["contract"].(string)
		collection := nftCollections[contractAddress]
		res = append(res, &NFT{
			WalletNFT:          wn,
			Name:               collection.Name,
			Description:        collection.Description,
			CollectionImageURI: collection.CollectionImageURI,
		})
	}

	return res
}

func (c *coinsRepository) getNFTCollections(ctx context.Context, network string, contractAddresses []string) (res map[string]*NFT, missing []string, err error) {
	nfts, err := storage.Select[nft](ctx, c.db, `SELECT * FROM nft_collections WHERE network = $1 AND contract_address = ANY($2)`, network, contractAddresses)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to get local nfts for %v %+v", network, contractAddresses)
	}
	if len(nfts) < len(contractAddresses) {
		missing = make([]string, 0, len(contractAddresses)-len(nfts))
		for _, contract := range contractAddresses {
			found := false
			for _, n := range nfts {
				if n.ContractAddress == contract {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, contract)
			}
		}
	}
	res = make(map[string]*NFT, len(nfts))
	for _, r := range nfts {
		res[r.ContractAddress] = &NFT{
			Name:               r.Name,
			Description:        r.Description,
			CollectionImageURI: r.IconUrl,
		}
	}
	return res, missing, nil
}

func (c *coinsRepository) importNFTCollections(ctx context.Context, network string, nftsToImport []WalletNFT, contractAddresses []string) (map[string]*NFT, error) {
	err := c.insertNFTs(ctx, network, nftsToImport)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to import nfts %+v", contractAddresses)
	}
	updatedNfts := make(map[string]*NFT, len(nftsToImport))
	tErr := storage.DoInTransaction(ctx, c.db, func(conn storage.QueryExecer) error {
		_, err := storage.ExecMany[nft](ctx, conn, `SELECT * from nft_collections where contract_address = ANY($1) FOR UPDATE`, contractAddresses)
		if err != nil {
			return errors.Wrapf(err, "failed to select for update nfts %#v", contractAddresses)
		}
		var errGroup errgroup.Group
		nftData := make(chan *coingecko.NFT, len(contractAddresses))
		for _, contract := range contractAddresses {
			errGroup.Go(func() error {
				nftItem, nftErr := c.nftCoinGeckoClient.GetNFT(ctx, network, contract)
				if nftErr != nil {
					return errors.Wrapf(nftErr, "failed to fetch nft data from coin gecko %v %v", network, contract)
				}
				nftData <- nftItem
				return nil
			})
		}
		if syncNftErr := errGroup.Wait(); syncNftErr != nil {
			return errors.Wrapf(syncNftErr, "failed to fetch nft data from coin gecko")
		}
		close(nftData)
		nftsToUpdate := []*coingecko.NFT{}
		for nftItem := range nftData {
			nftsToUpdate = append(nftsToUpdate, nftItem)
		}
		var uErr error
		updatedNfts, uErr = c.updateNFTCollections(ctx, conn, nftsToUpdate)
		if uErr != nil {
			return errors.Wrapf(uErr, "failed to update nft data in db with coin gecko data %#v", nftsToUpdate)
		}
		return nil
	})
	return updatedNfts, errors.Wrapf(tErr, "failed to update nfts from coin gecko")
}
func (c *coinsRepository) insertNFTs(ctx context.Context, network string, nftsToImport []WalletNFT) error {
	placeholders, params := buildNftsInsert(strings.ToLower(network), nftsToImport)
	_, err := storage.Exec(ctx, c.db, fmt.Sprintf("INSERT INTO nft_collections(network, name, description, token_standard, contract_address, symbol, icon_url)  VALUES %v ON CONFLICT(contract_address) DO NOTHING;", placeholders), params...)
	return errors.Wrapf(err, "failed to insert nfts (wallet data)")
}

func (c *coinsRepository) updateNFTCollections(ctx context.Context, conn storage.QueryExecer, nfts []*coingecko.NFT) (map[string]*NFT, error) {
	placeholders, params := buildNftsUpdate(nfts)
	nftsUpdated, err := storage.ExecMany[nft](ctx, conn, fmt.Sprintf(`
			UPDATE nft_collections SET
			             description = update_data.description,
						 name = update_data.name,
						 symbol = update_data.symbol,
						 icon_url = update_data.icon_url
			FROM (
				VALUES %v
			) as update_data (
				contract_address, description, name, symbol, icon_url
			)
			WHERE nft_collections.contract_address = update_data.contract_address
			RETURNING nft_collections.*
`, placeholders), params...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to update nft data in db with coin gecko data %#v", nfts)
	}
	res := make(map[string]*NFT, len(nftsUpdated))
	for _, r := range nftsUpdated {
		res[r.ContractAddress] = &NFT{
			Name:               r.Name,
			Description:        r.Description,
			CollectionImageURI: r.IconUrl,
		}
	}
	return res, nil
}

func buildNftsInsert(network string, nftsToImport []WalletNFT) (sql string, params []any) {
	placeholders := make([]string, 0, len(nftsToImport))
	idx := 1
	params = make([]any, 0, len(nftsToImport)*8)
	for _, n := range nftsToImport {
		params = append(params, network, "", "", n["kind"], n["contract"], n["symbol"], "")
		placeholders = append(placeholders, fmt.Sprintf("($%[1]v, $%[2]v,$%[3]v, $%[4]v, $%[5]v, $%[6]v, $%[7]v)", idx, idx+1, idx+2, idx+3, idx+4, idx+5, idx+6))
		idx += 7
	}
	return strings.Join(placeholders, ", "), params
}
func buildNftsUpdate(nftsToImport []*coingecko.NFT) (sql string, params []any) {
	placeholders := make([]string, 0, len(nftsToImport))
	idx := 1
	params = make([]any, 0, len(nftsToImport)*5)
	for _, n := range nftsToImport {
		params = append(params, n.ContractAddress, n.Description, n.Name, n.Symbol, n.ImageUri())
		placeholders = append(placeholders, fmt.Sprintf("($%[1]v, $%[2]v,$%[3]v, $%[4]v, $%[5]v)", idx, idx+1, idx+2, idx+3, idx+4))
		idx += 5
	}
	return strings.Join(placeholders, ", "), params
}

func (n *NFT) MarshalJSON() ([]byte, error) {
	if n == nil {
		return []byte("null"), nil
	}
	values := map[string]any{}
	if n.WalletNFT != nil {
		values = n.WalletNFT
	}
	rNFT := reflect.TypeOf(n).Elem()
	rNFTVal := reflect.Indirect(reflect.ValueOf(n))
	for i := range rNFT.NumField() {
		field := rNFT.Field(i)
		if jsonTag := field.Tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			var opt string
			jsonTag, opt, _ = strings.Cut(jsonTag, ",")
			val := rNFTVal.FieldByName(field.Name)
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
