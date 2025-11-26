// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"fmt"
	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/pkg/errors"
	"math/big"
	"math/rand"
	"strings"
	"time"
)

func (t *tokenAnalytics) insertDummyDataProcessor(ctx context.Context) {
	t.dummyInsertBlockIdx = 74298420
	stream := "a69a079e-d500-42ee-af6d-22d5eb5b10df"
	err := t.createUser(ctx, "0xc6646173c7f997949494dfd87d2076ea41b801fb", "9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f")
	if err != nil {
		log.Panic(errors.Wrapf(err, "failed to insert token creator"))
	}
	err = t.generateToken(ctx, stream)
	if err != nil {
		log.Panic(errors.Wrapf(err, "failed to insert token data"))
	}
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		defer ticker.Stop()
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				insCtx, insCancel := context.WithTimeout(ctx, 4500*time.Millisecond)
				if err = t.generateBuysAndSells(insCtx, stream); err != nil {
					log.Error(errors.Wrapf(err, "failed to insert dummy tx data"))
				}
				insCancel()
			}
		}
	}()
}

func (t *tokenAnalytics) generateBuysAndSells(ctx context.Context, stream string) error {
	t.dummyInsertBlockIdx += 1
	blockHash, _ := randomHex(32)
	contractAddr := "0x7307Ea7aB4a7e5bcbA1bF18c9495d08107D9F0d8"
	txsForBlock := []string{}
	for txIdx := 0; txIdx < 100; txIdx++ {
		txHash, _ := randomHex(32)
		userBlockChainAddr, _ := randomHex(20)
		master, _ := randomHex(32)
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
		base, _ := hex.DecodeString(strings.TrimPrefix(t.cfg.IONTokenAddress, "0x"))
		txInput, err := bondingcurve.ABI.Methods["swap"].Inputs.Pack(
			[]byte(base),
			[]byte("0:9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f:"), // token creator, linked to data from token
			new(big.Int).SetInt64(amountBase),
			new(big.Int).SetInt64(amountTarget),
		)
		if err != nil {
			return err
		}
		logSwap := fmt.Sprintf(`{
          "address": "%[1]v",
          "data": "0x%[3]v",
          "logIndex": "0x1",
          "removed": false,
          "topics": [
            "0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0",
            "0x000000000000000000000000%[2]v",
            "0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"
          ]
        }`, contractAddr, userBlockChainAddr, hex.EncodeToString(data))

		tx := fmt.Sprintf(`{
      "accessList": [],
      "blockHash": "%[5]v",
      "blockNumber": "%[2]v",
      "blockTimestamp": "%[6]v",
      "chainId": "0x61",
      "from": "0x%[3]v",
      "gas": "0x14af2d",
      "gasPrice": "0x3b9aca00",
      "hash": "%[4]v",
      "input": "0x83362e17%[7]v",
      "logs": [`+logSwap+`],
      "maxFeePerGas": "0x4a817c800",
      "maxPriorityFeePerGas": "0x3b9aca00",
      "nonce": "0x6",
      "r": "0xcf368ec13b2f7dfaad0bde4aac890ff51636111bb8220dfdd904aeb975f5bc0f",
      "s": "0x229edc4496b34d243ac4980aa17955dd6928bf8f6077f386934249782b695545",
      "to": "%[1]v",
      "transactionIndex": "%[8]v",
      "type": "0x2",
      "v": "0x0",
      "value": "0x0",
      "yParity": "0x0"
	}`, contractAddr, t.dummyInsertBlockIdx, userBlockChainAddr, txHash, blockHash, time.Now().Unix(),
			hex.EncodeToString(txInput), txIdx)
		txsForBlock = append(txsForBlock, tx)
	}
	fullData := fmt.Sprintf(`{"stream": "%[1]v", "transactions": [`+strings.Join(txsForBlock, ",")+`]}`, stream)
	sql := `INSERT INTO smart_contract_transactions(from_block_number, to_block_number, network, stream_id, data)
			VALUES ($1, $1, 'bsc-testnet-dummy', $2, $3::JSONB)`
	_, err := storage.Exec(ctx, t.ingestedDataDB, sql, t.dummyInsertBlockIdx, stream, fullData)
	return errors.Wrapf(err, "failed to insert dummy tx data")
}

func (t *tokenAnalytics) generateToken(ctx context.Context, stream string) error {
	blockNum := t.dummyInsertBlockIdx
	data := fmt.Sprintf(`{
  "stream": "%[1]v",
  "transactions": [
    {
      "accessList": [],
      "blockHash": "0x1c818b62bab665dc5227957887d03d354ed2d8ea2048d126610d8b78d389a4a8",
      "blockNumber": "%[1]v",
      "blockTimestamp": "0x6922196d",
      "chainId": "0x61",
      "from": "0xc6646173c7f997949494dfd87d2076ea41b801fb",
      "gas": "0x14af2d",
      "gasPrice": "0x3b9aca00",
      "hash": "0xca64f6900600d702d5c28d2f63b3ad96aa3c97590bf2348e28d13e56e99141a7",
      "input": "0x83362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000dbd2fc137a3000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000043303a396462663366313936333130666234613138313866363139613638366231356536666661373864373233653834333937336663646339313235663135626332663a0000000000000000000000000000000000000000000000000000000000",
      "logs": [
        {
          "address": "0x7307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8",
          "data": "0x",
          "logIndex": "0x1",
          "removed": false,
          "topics": [
            "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000008d86c992ce7812a64101da9b2531d5f378d682e2"
          ]
        },
        {
          "address": "0x7307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8",
          "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
          "logIndex": "0x2",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000008d86c992ce7812a64101da9b2531d5f378d682e2"
          ]
        },
        {
          "address": "0x7307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8",
          "data": "0x00000000000000000000000000000000000000000000d3c21bcecceda1000000",
          "logIndex": "0x3",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000008d86c992ce7812a64101da9b2531d5f378d682e2"
          ]
        },
        {
          "address": "0x8d86c992ce7812a64101da9b2531d5f378d682e2",
          "data": "0x000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000d3c21bcecceda1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000043303a396462663366313936333130666234613138313866363139613638366231356536666661373864373233653834333937336663646339313235663135626332663a0000000000000000000000000000000000000000000000000000000000",
          "logIndex": "0x4",
          "removed": false,
          "topics": [
            "0xcaa54a9b9817e12b67fd790dabf6f963cb9a083290c5c06c052ea18bb9b29427",
            "0x0000000000000000000000007307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8"
          ]
        },
        {
          "address": "0x8d86c992ce7812a64101da9b2531d5f378d682e2",
          "data": "0x000000000000000000000000c6646173c7f997949494dfd87d2076ea41b801fb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000008d86c992ce7812a64101da9b2531d5f378d682e2",
          "logIndex": "0x5",
          "removed": false,
          "topics": [
            "0xc391f1439e6a5d64454067a61cc30295e026850c66d0dcb87e5c74c455862408",
            "0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"
          ]
        },
        {
          "address": "0x8d86c992ce7812a64101da9b2531d5f378d682e2",
          "data": "0x",
          "logIndex": "0x6",
          "removed": false,
          "topics": [
            "0x157b5bda8c36b5ae40a6f0d041dce8790309b04707aa024e9a73ee87287372b4",
            "0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15",
            "0x0000000000000000000000002c73996babf1a06c2c057177353293f7ca0907c8",
            "0x0000000000000000000000007307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8"
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
            "0x0000000000000000000000008d86c992ce7812a64101da9b2531d5f378d682e2"
          ]
        },
        {
          "address": "0x7307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8",
          "data": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "logIndex": "0x8",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x0000000000000000000000008d86c992ce7812a64101da9b2531d5f378d682e2",
            "0x000000000000000000000000c6646173c7f997949494dfd87d2076ea41b801fb"
          ]
        },
        {
          "address": "0x8d86c992ce7812a64101da9b2531d5f378d682e2",
          "data": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000000",
          "logIndex": "0x9",
          "removed": false,
          "topics": [
            "0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0",
            "0x000000000000000000000000c6646173c7f997949494dfd87d2076ea41b801fb",
            "0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"
          ]
        },
        {
          "address": "0x8d86c992ce7812a64101da9b2531d5f378d682e2",
          "data": "0x0000000000000000000000000000000000000000000000000dbd2fc137a300000000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "logIndex": "0xa",
          "removed": false,
          "topics": [
            "0x65184e4e64eca5b9cd1401ff3001ac8803c660b9ac3bf7af10b7fae4b146b446",
            "0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"
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
}`, blockNum, stream)
	sql := `INSERT INTO smart_contract_transactions(from_block_number, to_block_number, network, stream_id, data)
			VALUES ($1, $1, 'bsc-testnet-dummy', $2, $3::JSONB)`
	_, err := storage.Exec(ctx, t.ingestedDataDB, sql, blockNum, stream, data)
	return errors.Wrapf(err, "failed to insert dummy contract data")
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
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
	_, err := storage.Exec(ctx, t.ingestedDataDB, `
		INSERT INTO users (
			created_at, updated_at, id, master_pubkey, blockchain_address, username, 
			display_name, lookup, ion_connect_relays, verified
		) VALUES (
			NOW(), NOW(), $1, $2, $3, $4, $5, $6, $7, $8
		)
		ON CONFLICT (master_pubkey) 
		DO UPDATE SET
			updated_at = NOW(),
			id = EXCLUDED.id,
			username = EXCLUDED.username,
			display_name = EXCLUDED.display_name,
			lookup = EXCLUDED.lookup,
			ion_connect_relays = EXCLUDED.ion_connect_relays,
			verified = EXCLUDED.verified
	`, id, masterPubkey, blockchainAddress, username, displayName, lookup, ionConnectRelays, verified)
	if err != nil {
		return fmt.Errorf("failed to upsert user %v: %w", masterPubkey, err)
	}

	return nil
}
