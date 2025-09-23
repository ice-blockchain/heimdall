// SPDX-License-Identifier: ice License 1.0

package nftcontent

import (
	"context"
	_ "embed"
	"io"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

const (
	NFTContentTypeUser    NFTContentType = "user"
	NFTContentTypeAccount NFTContentType = "account"
	NFTContentTypePost    NFTContentType = "post"
	NFTContentTypeArticle NFTContentType = "article"
	NFTContentTypeVideo   NFTContentType = "video"
	NFTContentTypeStory   NFTContentType = "story"

	NFTCategoryPost    NFTCategory = "Post"
	NFTCategoryVideo   NFTCategory = "Video"
	NFTCategoryStory   NFTCategory = "Story"
	NFTCategoryArticle NFTCategory = "Article"

	NFTContentStatusNew       NFTContentStatus = "new"
	NFTContentStatusPending   NFTContentStatus = "pending"
	NFTContentStatusCompleted NFTContentStatus = "completed"
)

type (
	NFTContentStatus    = string
	NFTContentType      = string
	NFTCategory         = string
	OwnerAddressFetcher interface {
		FetchMainWallet(ctx context.Context, masterKey string) (accounts.Wallet, error)
		SetProviderForUnsupportedNFTs(nft accounts.NFTInWallets)
	}
	NFTContent interface {
		io.Closer
		HealthCheck(ctx context.Context) error
		Process(ctx context.Context, events model.Events) error
		GetNFTCollectionItemMetadata(ctx context.Context, nftContentType, contentAddress string) (*NFTResponse, *NFTCollectionMetadata, error)
		GetNFTCollectionMetadata(ctx context.Context, masterPubkey string) (*NFTResponse, *NFTCollectionMetadata, error)
		ListNFTs(ctx context.Context, walletAddr, paginationToken string, limit uint) ([]WalletNFT, *string, error)
	}
	NFTCollectionMetadata struct {
		NFTCollectionAddress        string `db:"nft_collection_address"`
		NFTCollectionName           string `db:"nft_collection_name"`
		NFTCollectionCreatorAddress string `db:"nft_collection_creator_address"`
		NFTItemAddress              string `db:"nft_item_address"`
	}
	NFTCollectionItemMetadata struct {
		NFTCollectionMetadata
		Username       string           `db:"username"`
		DisplayName    string           `db:"display_name"`
		ContentAddress string           `db:"content_address"`
		MasterPubKey   string           `db:"master_pubkey"`
		Owner          string           `db:"owner"`
		Type           NFTContentType   `db:"type"`
		Status         NFTContentStatus `db:"status"`
		Bio            *string          `db:"bio"`
	}
	NFTResponse struct {
		Type           NFTContentType `json:"type,omitempty" example:"Content"`
		Name           string         `json:"name,omitempty" example:"John Doe's ION profile"`
		Description    string         `json:"description,omitempty" example:"Official ION Account for John Doe"`
		Image          string         `json:"image,omitempty" example:"https://example.com/image.png"`
		Symbol         string         `json:"symbol,omitempty" example:"johndoe"`
		HtmlPreviewUri string         `json:"html_preview_uri,omitempty" example:"https://example.com/html_preview.html"`
		AccountID      string         `json:"account_id,omitempty" example:"johndoe"`
		ProfileUri     string         `json:"profile_uri,omitempty" example:"https://example.com/account/address"`
		DisplayName    string         `json:"display_name,omitempty" example:"John Doe"`
		Bio            string         `json:"bio,omitempty" example:"Official ION Account for John Doe"`
		ContentUri     string         `json:"content_uri,omitempty" example:"https://example.com/account/address"`
		ContentType    string         `json:"content_type,omitempty" example:"text/html"`
		AuthorID       string         `json:"author_id,omitempty" example:"john doe"`
		Category       []NFTCategory  `json:"category,omitempty" example:"[Video, Post]"`
		Tags           []string       `json:"tags,omitempty"`
		Attributes     [][]string     `json:"attributes,omitempty"`
	}

	Config struct {
		ProfileURIBaseURL  string `yaml:"profileUriBaseUrl"`
		HTMLPreviewBaseURL string `yaml:"htmlPreviewBaseUrl"`
		ContentURIBaseURL  string `yaml:"contentUriBaseUrl"`
		Indexer            struct {
			ION string `yaml:"ion"  mapstructure:"ion"`
		} `yaml:"indexer" mapstructure:"indexer"`
	}

	WalletNFT = coins.WalletNFT
)

var (
	ErrForbiddenContent     = errors.New("forbidden content")
	ErrNotFound             = errors.New("not found")
	ErrOnBehalfAccessDenied = model.ErrOnBehalfAccessDenied
)

const (
	CollectionMetadataIndexedKey = coins.CollectionMetadataIndexedKey
	applicationYamlKey           = "nft-content"

	nftResponseName        string = "NFT response name"
	nftResponseDescription string = "NFT response description"

	contentTypeHtml string = "text/html"

	responseContentType         string = "Content"
	responseAccountType         string = "Account"
	defaultWalletNetworkTestNet        = "IonTestnet"
	defaultWalletNetworkMainNet        = "Ion"
)

var (
	//go:embed DDL.sql
	ddl string

	imageUrlMap = map[NFTContentType]string{
		NFTContentTypeUser:    "https://cdn.ice.io/nft/assets/collection.png",
		NFTContentTypeAccount: "http://cdn.ice.io/nft/assets/account.png",
		NFTContentTypeVideo:   "https://cdn.ice.io/nft/assets/video.png",
		NFTContentTypeStory:   "https://cdn.ice.io/nft/assets/stories.png",
		NFTContentTypePost:    "https://cdn.ice.io/nft/assets/post.png",
		NFTContentTypeArticle: "https://cdn.ice.io/nft/assets/article.png",
	}
	defaultIndexerReqLimit = uint(100)
)

type (
	nftContent struct {
		db            *storage.DB
		config        *Config
		walletFetcher OwnerAddressFetcher
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
)
