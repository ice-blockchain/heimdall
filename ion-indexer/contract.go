// SPDX-License-Identifier: ice License 1.0

package ion_indexer

import (
	"context"

	"github.com/ice-blockchain/heimdall/coins"
)

type (
	WalletHistoryItem map[string]any
	Indexer           interface {
		ListNFTs(ctx context.Context, walletAddr string, paginationToken string, limit uint) ([]coins.WalletNFT, *string, error)
		WalletTransactions(ctx context.Context, walletId, walletAddr, paginationToken string, limit uint) ([]WalletHistoryItem, *string, error)
		GetBalance(ctx context.Context, walletAddr string) ([]Asset, error)
	}
	WalletNFT = coins.WalletNFT
	Asset     map[string]any
)

type (
	indexer struct {
		config  *config
		testnet bool
	}
	config struct {
		ION string `yaml:"ion"  mapstructure:"ion"`
	}

	getNftItemsIndexerResponse struct {
		NftItems []nftItem               `json:"nft_items"`
		Metadata map[string]metadataItem `json:"metadata"`
	}
	metadataItem struct {
		IsIndexed bool `json:"is_indexed"`
		TokenInfo []struct {
			Type        string `json:"type"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Image       string `json:"image"`
			Symbol      string `json:"symbol"`
			Extra       struct {
				ImageBig       string `json:"_image_big"`
				ImageMedium    string `json:"_image_medium"`
				ImageSmall     string `json:"_image_small"`
				AccountId      string `json:"account_id"`
				AuthorId       string `json:"author_id"`
				DisplayName    string `json:"display_name"`
				HtmlPreviewUri string `json:"html_preview_uri"`
				ProfileUri     string `json:"profile_uri"`
				Type           string `json:"type"`
				Uri            string `json:"uri"`
			} `json:"extra"`
		} `json:"token_info"`
	}
	nftItem struct {
		Address           string `json:"address"`
		Init              bool   `json:"init"`
		Index             string `json:"index"`
		CollectionAddress string `json:"collection_address"`
		OwnerAddress      string `json:"owner_address"`
		Content           struct {
			Uri string `json:"uri"`
		} `json:"content"`
		LastTransactionLt string `json:"last_transaction_lt"`
		CodeHash          string `json:"code_hash"`
		DataHash          string `json:"data_hash"`
		Collection        struct {
			Address           string `json:"address"`
			OwnerAddress      string `json:"owner_address"`
			LastTransactionLt string `json:"last_transaction_lt"`
			NextItemIndex     string `json:"next_item_index"`
			CollectionContent struct {
				Uri string `json:"uri"`
			} `json:"collection_content"`
			DataHash string `json:"data_hash"`
			CodeHash string `json:"code_hash"`
		} `json:"collection"`
	}

	getTransactionsIndexerResponse struct {
		Transactions []transaction `json:"transactions"`
	}
	transaction struct {
		Account                  string `json:"account"`
		Hash                     string `json:"hash"`
		Lt                       string `json:"lt"`
		Now                      int64  `json:"now"`
		McBlockSeqno             int64  `json:"mc_block_seqno"`
		TraceId                  string `json:"trace_id"`
		PrevTransHash            string `json:"prev_trans_hash"`
		PrevTransLt              string `json:"prev_trans_lt"`
		OrigStatus               string `json:"orig_status"`
		EndStatus                string `json:"end_status"`
		TotalFees                string `json:"total_fees"`
		TotalFeesExtraCurrencies struct {
		} `json:"total_fees_extra_currencies"`
		Description struct {
			Type        string `json:"type"`
			Aborted     bool   `json:"aborted"`
			Destroyed   bool   `json:"destroyed"`
			CreditFirst bool   `json:"credit_first"`
			StoragePh   struct {
				StorageFeesCollected string `json:"storage_fees_collected"`
				StatusChange         string `json:"status_change"`
			} `json:"storage_ph"`
			ComputePh struct {
				Skipped          bool   `json:"skipped"`
				Success          bool   `json:"success,omitempty"`
				MsgStateUsed     bool   `json:"msg_state_used,omitempty"`
				AccountActivated bool   `json:"account_activated,omitempty"`
				GasFees          string `json:"gas_fees,omitempty"`
				GasUsed          string `json:"gas_used,omitempty"`
				GasLimit         string `json:"gas_limit,omitempty"`
				GasCredit        string `json:"gas_credit,omitempty"`
				Mode             int    `json:"mode,omitempty"`
				ExitCode         int    `json:"exit_code,omitempty"`
				VmSteps          int    `json:"vm_steps,omitempty"`
				VmInitStateHash  string `json:"vm_init_state_hash,omitempty"`
				VmFinalStateHash string `json:"vm_final_state_hash,omitempty"`
				Reason           string `json:"reason,omitempty"`
			} `json:"compute_ph"`
			Action struct {
				Success         bool   `json:"success"`
				Valid           bool   `json:"valid"`
				NoFunds         bool   `json:"no_funds"`
				StatusChange    string `json:"status_change"`
				TotalFwdFees    string `json:"total_fwd_fees"`
				TotalActionFees string `json:"total_action_fees"`
				ResultCode      int    `json:"result_code"`
				TotActions      int    `json:"tot_actions"`
				SpecActions     int    `json:"spec_actions"`
				SkippedActions  int    `json:"skipped_actions"`
				MsgsCreated     int    `json:"msgs_created"`
				ActionListHash  string `json:"action_list_hash"`
				TotMsgSize      struct {
					Cells string `json:"cells"`
					Bits  string `json:"bits"`
				} `json:"tot_msg_size"`
			} `json:"action,omitempty"`
		} `json:"description"`
		BlockRef struct {
			Workchain int    `json:"workchain"`
			Shard     string `json:"shard"`
			Seqno     int    `json:"seqno"`
		} `json:"block_ref"`
		InMsg              msg   `json:"in_msg"`
		OutMsgs            []msg `json:"out_msgs"`
		AccountStateBefore struct {
			Hash            string  `json:"hash"`
			Balance         *string `json:"balance"`
			ExtraCurrencies *struct {
			} `json:"extra_currencies"`
			AccountStatus *string     `json:"account_status"`
			FrozenHash    interface{} `json:"frozen_hash"`
			DataHash      interface{} `json:"data_hash"`
			CodeHash      interface{} `json:"code_hash"`
		} `json:"account_state_before"`
		AccountStateAfter struct {
			Hash            string `json:"hash"`
			Balance         string `json:"balance"`
			ExtraCurrencies struct {
			} `json:"extra_currencies"`
			AccountStatus string      `json:"account_status"`
			FrozenHash    interface{} `json:"frozen_hash"`
			DataHash      *string     `json:"data_hash"`
			CodeHash      *string     `json:"code_hash"`
		} `json:"account_state_after"`
		Emulated bool `json:"emulated"`
	}
	msg struct {
		Hash                 string `json:"hash"`
		Source               string `json:"source"`
		Destination          string `json:"destination"`
		Value                string `json:"value"`
		ValueExtraCurrencies struct {
		} `json:"value_extra_currencies"`
		FwdFee         string      `json:"fwd_fee"`
		IhrFee         string      `json:"ihr_fee"`
		CreatedLt      string      `json:"created_lt"`
		CreatedAt      string      `json:"created_at"`
		Opcode         interface{} `json:"opcode"`
		IhrDisabled    bool        `json:"ihr_disabled"`
		Bounce         bool        `json:"bounce"`
		Bounced        bool        `json:"bounced"`
		ImportFee      interface{} `json:"import_fee"`
		MessageContent struct {
			Hash    string      `json:"hash"`
			Body    string      `json:"body"`
			Decoded interface{} `json:"decoded"`
		} `json:"message_content"`
		InitState *struct {
			Hash    string      `json:"hash"`
			Body    string      `json:"body"`
			Decoded interface{} `json:"decoded"`
		} `json:"init_state"`
	}

	accountStateResponse struct {
		Accounts []accountState `json:"accounts"`
	}
	accountState struct {
		Address             string   `json:"address"`
		AccountStateHash    string   `json:"account_state_hash"`
		Balance             string   `json:"balance"`
		ExtraCurrencies     struct{} `json:"extra_currencies"`
		Status              string   `json:"status"`
		LastTransactionHash string   `json:"last_transaction_hash"`
		LastTransactionLt   string   `json:"last_transaction_lt"`
		DataHash            string   `json:"data_hash"`
		CodeHash            string   `json:"code_hash"`
	}
)

const (
	NFTCollectionMetadataIndexedKey = coins.CollectionMetadataIndexedKey
	applicationYamlKey              = "indexer"
	defaultIndexerReqLimit          = uint(100)
)
