// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) insertDummyDataProcessor(ctx context.Context) {
	t.dummyInsertBlockIdx = 74298420
	stream := "a69a079e-d500-42ee-af6d-22d5eb5b10df"
	err := t.generateToken(ctx, stream, &tokenRow{
		ContractAddress:     "7307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8",
		CreatorMasterPubkey: "9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f",
		ExternalAddress:     "ion_connect:0:9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f:",
		Title:               "Yu's token",
		Ticker:              "posidoniusenara",
		TotalSupply:         "1000000000000000000000000",
		BaseToken:           "2c73996BaBF1a06c2C057177353293f7cA0907c8",
		PairId:              "0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15",
		CreatorVerified:     false,
	})
	if err != nil {
		log.Panic(errors.Wrapf(err, "failed to insert token data"))
	}
	tokenData, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, `
		SELECT 
			created_at,
			updated_at,
			log_index,
			contract_address,
			external_address,
			platform,
			type,
		    ticker AS title, 
			total_supply, 
			creator_master_pubkey,
		    base_token,
			pair_id,
			market_cap_usd,
			price_usd,
		    holders_count
		FROM tokens
		ORDER BY created_at DESC LIMIT 100
	`)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to get token data for dummy tx generation"))
		return
	}
	for _, token := range tokenData {
		t.startBuysOrSellsProcessor(ctx, token, stream)
	}
	t.startNewTokenGenerator(ctx, uuid.NewString())
}

func (t *tokenAnalytics) startNewTokenGenerator(ctx context.Context, stream string) {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		defer ticker.Stop()
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				insCtx, insCancel := context.WithTimeout(ctx, 4500*time.Millisecond)
				master := mustRandomHex(32)
				kinds := []int{0, 30023, 30023, 30175}
				kind := kinds[rand.Intn(len(kinds)-1)]
				dTag := uuid.NewString()
				if kind == 0 {
					dTag = ""
				}
				names := []string{
					"Super Duper Token",
					"Giga token",
					"ToTheMooN",
					"HODL token",
				}
				displayName := names[rand.Int31n(int32(len(names)-1))]
				symbol := strings.ToLower(strings.ReplaceAll(displayName, " ", ""))
				tok := &tokenRow{
					ContractAddress:     mustRandomHex(20),
					CreatorMasterPubkey: master,
					ExternalAddress:     fmt.Sprintf("ion_connect:%v:%v:%v", kind, master, dTag),
					Title:               displayName,
					Ticker:              symbol,
					TotalSupply:         "1000000000000000000" + strings.Repeat("0", rand.Intn(8)+1),
					BaseToken:           strings.TrimPrefix(t.cfg.IONTokenAddress, "0x"),
					PairId:              "0x" + mustRandomHex(32),
					CreatorVerified:     rand.Intn(2) == 0,
				}
				if err := t.generateToken(insCtx, stream, tok); err != nil {
					log.Error(errors.Wrapf(err, "failed to insert dummy tx data"))
				}
				insCancel()
				t.startBuysOrSellsProcessor(ctx, tok, stream)
			}
		}
	}()
}

func (t *tokenAnalytics) startBuysOrSellsProcessor(ctx context.Context, tokenData *tokenRow, stream string) {
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		defer ticker.Stop()
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				insCtx, insCancel := context.WithTimeout(ctx, 4500*time.Millisecond)
				if err := t.generateBuyOrSellBatch(insCtx, stream, tokenData); err != nil {
					log.Error(errors.Wrapf(err, "failed to insert dummy tx data"))
				}
				insCancel()
			}
		}
	}()
}

func (t *tokenAnalytics) generateBuyOrSellBatch(ctx context.Context, stream string, token *tokenRow) error {
	blockNum := atomic.AddUint64(&t.dummyInsertBlockIdx, 1)
	txsForBlock := []string{}
	for txIdx := 0; txIdx < 100; txIdx++ {
		userBlockChainAddr := mustRandomHex(20)
		master := mustRandomHex(32)
		if err := t.createUser(ctx, "0x"+userBlockChainAddr, master); err != nil {
			return err
		}
		buyOrSel := rand.Intn(2) == 0
		maxValForTransfer, _ := new(big.Float).SetFloat64(10 * 1e18).Int64()
		amountBase := rand.Int63n(maxValForTransfer)
		amountTarget := rand.Int63n(maxValForTransfer)
		data, err := bondingcurve.ABI.Events["Swapped"].Inputs.NonIndexed().Pack(
			buyOrSel,
			new(big.Int).SetInt64(amountBase),
			new(big.Int).SetInt64(amountTarget),
			new(big.Int).SetInt64(0),
		)
		if err != nil {
			return err
		}
		base, _ := hex.DecodeString(strings.TrimPrefix(token.BaseToken, "0x"))
		txInput, err := bondingcurve.ABI.Methods["swap"].Inputs.Pack(
			base,
			[]byte(token.ExternalAddress), // token creator, linked to data from token
			new(big.Int).SetInt64(amountBase),
			new(big.Int).SetInt64(amountTarget),
		)
		if err != nil {
			return err
		}
		tmpl, err := template.New("swap_tx").Parse(`{
      "accessList": [],
      "blockHash": "0x{{.BlockHash}}",
      "blockNumber": "{{.BlockNumber}}",
      "blockTimestamp": "{{.BlockTimestamp}}",
      "chainId": "0x61",
      "from": "0x{{.UserBlockchainAddr}}",
      "gas": "0x14af2d",
      "gasPrice": "0x3b9aca00",
      "hash": "0x{{.TxHash}}",
      "input": "0x83362e17{{.TxInput}}",
      "logs": [{
          "address": "0x{{.Token.ContractAddress}}",
          "data": "0x{{.SwappedData}}",
          "logIndex": "0x1",
          "removed": false,
          "topics": [
            "0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0",
            "0x000000000000000000000000{{.UserBlockchainAddr}}",
            "{{.Token.PairId}}"
          ]
        }],
      "maxFeePerGas": "0x4a817c800",
      "maxPriorityFeePerGas": "0x3b9aca00",
      "nonce": "0x6",
      "r": "0xcf368ec13b2f7dfaad0bde4aac890ff51636111bb8220dfdd904aeb975f5bc0f",
      "s": "0x229edc4496b34d243ac4980aa17955dd6928bf8f6077f386934249782b695545",
      "to": "0x{{.Token.ContractAddress}}",
      "transactionIndex": "{{.TxIndex}}",
      "type": "0x2",
      "v": "0x0",
      "value": "0x0",
      "yParity": "0x0"
	}`)
		if err != nil {
			return errors.Wrapf(err, "failed to insert dummy contract data: malformed template")
		}
		buf := bytes.NewBuffer([]byte{})
		bondingCurveNoPrefix := strings.TrimPrefix(t.bondingCurveContractAddress, "0x")
		err = tmpl.Execute(buf, &templateParams{
			Stream:               stream,
			BlockNumber:          blockNum,
			BlockTimestamp:       uint64(time.Now().Unix()),
			TxIndex:              1,
			BlockHash:            mustRandomHex(32),
			TxHash:               mustRandomHex(32),
			Token:                token,
			UserBlockchainAddr:   userBlockChainAddr,
			TxInput:              hex.EncodeToString(txInput),
			BondingCurveContract: bondingCurveNoPrefix,
			SwappedData:          hex.EncodeToString(data),
		})
		if err != nil {
			return errors.Wrapf(err, "failed to insert dummy contract data: malformed template")
		}

		//, token.ContractAddress, t.dummyInsertBlockIdx, userBlockChainAddr, txHash, blockHash, time.Now().Unix(),
		//	hex.EncodeToString(txInput), txIdx)
		txsForBlock = append(txsForBlock, buf.String())
	}
	fullData := fmt.Sprintf(`{"stream": "%[1]v", "transactions": [`+strings.Join(txsForBlock, ",")+`]}`, stream)
	sql := `INSERT INTO smart_contract_transactions(from_block_number, to_block_number, network, stream_id, data)
			VALUES ($1, $1, 'bsc-testnet-dummy', $2, $3::JSONB)`
	_, err := storage.Exec(ctx, t.ingestedDataDB, sql, t.dummyInsertBlockIdx, stream, fullData)
	return errors.Wrapf(err, "failed to insert dummy tx data")
}

func (t *tokenAnalytics) generateToken(ctx context.Context, stream string, row *tokenRow) error {
	blockNum := atomic.AddUint64(&t.dummyInsertBlockIdx, 1)
	txHash := mustRandomHex(32)
	blockHash := mustRandomHex(32)
	ownerBlockchainAddr := mustRandomHex(20)
	ownerMasterKey := row.CreatorMasterPubkey
	err := t.createUser(ctx, "0x"+ownerBlockchainAddr, ownerMasterKey)
	base, _ := hex.DecodeString(strings.TrimPrefix(t.cfg.IONTokenAddress, "0x"))
	totalSupply, _ := new(big.Int).SetString(row.TotalSupply, 10)
	txInput, err := bondingcurve.ABI.Methods["swap"].Inputs.Pack(
		base,
		[]byte(row.ExternalAddress), // token creator, linked to data from token
		totalSupply,
		totalSupply,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to pack token created tx input")
	}
	bondedTokenCreatedData, err := bondingcurve.ABI.Events["BondedTokenCreated"].Inputs.NonIndexed().Pack(
		row.Title,
		row.Ticker,
		row.ExternalAddress,
		totalSupply,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to pack bondedTokenCreatedData")
	}
	tmpl, err := template.New("token").Parse(`{
  "stream": "{{.Stream}}",
  "transactions": [
    {
      "accessList": [],
      "blockHash": "0x1c818b62bab665dc5227957887d03d354ed2d8ea2048d126610d8b78d389a4a8",
      "blockNumber": "{{.BlockNumber}}",
      "blockTimestamp": "{{.BlockTimestamp}}",
      "chainId": "0x61",
      "from": "0x{{.CreatorBlockchainAddress}}",
      "gas": "0x14af2d",
      "gasPrice": "0x3b9aca00",
      "hash": "0x{{.TxHash}}",
      "input": "{{.TxInput}}",
      "logs": [
        {
	  "address": "0x{{.Token.ContractAddress}}",
          "data": "0x",
          "logIndex": "0x1",
          "removed": false,
          "topics": [
            "0x{{.BondingCurveContract}}",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x000000000000000000000000{{.BondingCurveContract}}"
          ]
        },
        {
          "address": "0x{{.Token.ContractAddress}}",
          "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
          "logIndex": "0x2",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x000000000000000000000000{{.BondingCurveContract}}"
          ]
        },
        {
          "address": "0x{{.Token.ContractAddress}}",
          "data": "0x00000000000000000000000000000000000000000000d3c21bcecceda1000000",
          "logIndex": "0x3",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x000000000000000000000000{{.BondingCurveContract}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "{{.BondedTokenCreatedData}}",
          "logIndex": "0x4",
          "removed": false,
          "topics": [
            "0xcaa54a9b9817e12b67fd790dabf6f963cb9a083290c5c06c052ea18bb9b29427",
            "0x000000000000000000000000{{.Token.ContractAddress}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "0x000000000000000000000000c6646173c7f997949494dfd87d2076ea41b801fb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000008d86c992ce7812a64101da9b2531d5f378d682e2",
          "logIndex": "0x5",
          "removed": false,
          "topics": [
            "0xc391f1439e6a5d64454067a61cc30295e026850c66d0dcb87e5c74c455862408",
            "0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "0x",
          "logIndex": "0x6",
          "removed": false,
          "topics": [
            "0x157b5bda8c36b5ae40a6f0d041dce8790309b04707aa024e9a73ee87287372b4",
            "{{.Token.PairId}}",
            "0x000000000000000000000000{{.Token.BaseToken}}",
            "0x000000000000000000000000{{.Token.ContractAddress}}"
          ]
        },
        {
          "address": "0x2c73996babf1a06c2c057177353293f7ca0907c8",
          "data": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "logIndex": "0x7",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x000000000000000000000000c6646173c7f997949494dfd87d2076ea41b801fb",
            "0x000000000000000000000000{{.BondingCurveContract}}"
          ]
        },
        {
          "address": "0x{{.Token.ContractAddress}}",
          "data": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "logIndex": "0x8",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x0000000000000000000000008d86c992ce7812a64101da9b2531d5f378d682e2",
            "0x000000000000000000000000{{.CreatorBlockchainAddress}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000000",
          "logIndex": "0x9",
          "removed": false,
          "topics": [
            "0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0",
            "0x000000000000000000000000{{.CreatorBlockchainAddress}}",
            "{{.Token.PairId}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "0x0000000000000000000000000000000000000000000000000dbd2fc137a300000000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "logIndex": "0xa",
          "removed": false,
          "topics": [
            "0x65184e4e64eca5b9cd1401ff3001ac8803c660b9ac3bf7af10b7fae4b146b446",
            "{{.Token.PairId}}"
          ]
        }
      ],
      "maxFeePerGas": "0x4a817c800",
      "maxPriorityFeePerGas": "0x3b9aca00",
      "nonce": "0x6",
      "r": "0xcf368ec13b2f7dfaad0bde4aac890ff51636111bb8220dfdd904aeb975f5bc0f",
      "s": "0x229edc4496b34d243ac4980aa17955dd6928bf8f6077f386934249782b695545",
      "to": "0x8d86c992ce7812a64101da9b2531d5f378d682e2",
      "transactionIndex": "0x1",
      "type": "0x2",
      "v": "0x0",
      "value": "0x0",
      "yParity": "0x0"
    }
  ]
}`)
	if err != nil {
		return errors.Wrapf(err, "failed to insert dummy contract data: malformed template")
	}
	buf := bytes.NewBuffer([]byte{})
	bondingCurveNoPrefix := strings.TrimPrefix(t.bondingCurveContractAddress, "0x")
	err = tmpl.Execute(buf, &templateParams{
		Stream:                   stream,
		BlockNumber:              blockNum,
		BlockTimestamp:           uint64(time.Now().Unix()),
		TxIndex:                  1,
		BlockHash:                blockHash,
		TxHash:                   txHash,
		Token:                    row,
		TxInput:                  "0x" + hex.EncodeToString(txInput),
		CreatorBlockchainAddress: ownerBlockchainAddr,
		BondingCurveContract:     bondingCurveNoPrefix,
		BondedTokenCreatedData:   "0x" + hex.EncodeToString(bondedTokenCreatedData),
	})
	if err != nil {
		return errors.Wrapf(err, "failed to insert dummy contract data: malformed template")
	}
	sql := `INSERT INTO smart_contract_transactions(from_block_number, to_block_number, network, stream_id, data)
			VALUES ($1, $1, 'bsc-testnet-dummy', $2, $3::JSONB)`
	_, err = storage.Exec(ctx, t.ingestedDataDB, sql, blockNum, stream, buf.String())
	return errors.Wrapf(err, "failed to insert dummy contract data")
}

func mustRandomHex(n int) string {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		log.Panic(errors.Wrapf(err, "failed to generate random"))
	}
	return hex.EncodeToString(bytes)
}

func (t *tokenAnalytics) createUser(ctx context.Context, blockchainAddress string, masterPubkey string) error {
	id := "us-" + blockchainAddress
	names := []string{
		"Diwata Lea",
		"Bohuslav Ferdinand",
		"Bethuel Gilbert",
		"Posidonius Enara",
		"Edwena İldar",
	}
	idx := rand.Int31n(int32(len(names) - 1))
	displayName := names[idx]
	username := strings.ToLower(strings.ReplaceAll(displayName, " ", ""))
	verified := rand.Intn(2) == 0
	lookup := strings.ToLower(strings.TrimSpace(username + " " + displayName))
	ionConnectRelays := []string{"wss://141.95.59.70:4443", "wss://181.41.142.217:4443", "wss://94.100.16.233:4443"}
	externalAddress := fmt.Sprintf("%s:%s", PlatformIonConnect, masterPubkey)
	_, err := storage.Exec(ctx, t.ingestedDataDB, `
		INSERT INTO users (
			created_at, updated_at, id, master_pubkey, blockchain_address, external_address, username, 
			display_name, lookup, ion_connect_relays, verified
		) VALUES (
			NOW(), NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9
		)
		ON CONFLICT (master_pubkey) 
		DO UPDATE SET
			updated_at = NOW(),
			id = EXCLUDED.id,
			blockchain_address = EXCLUDED.blockchain_address,
			external_address = EXCLUDED.external_address,
			username = EXCLUDED.username,
			display_name = EXCLUDED.display_name,
			lookup = EXCLUDED.lookup,
			ion_connect_relays = EXCLUDED.ion_connect_relays,
			verified = EXCLUDED.verified
	`, id, masterPubkey, blockchainAddress, externalAddress, username, displayName, lookup, ionConnectRelays, verified)
	if err != nil {
		return fmt.Errorf("failed to upsert user %v: %w", masterPubkey, err)
	}

	return nil
}

type templateParams struct {
	Stream                   string
	BlockNumber              uint64
	TxIndex                  uint64
	BlockHash                string
	TxHash                   string
	Token                    *tokenRow
	TxData                   string
	TxInput                  string
	CreatorBlockchainAddress string
	BondingCurveContract     string
	BondedTokenCreatedData   string
	SwappedData              string
	UserBlockchainAddr       string
	BlockTimestamp           uint64
}
