// SPDX-License-Identifier: ice License 1.0

package nftcontent

import (
	"context"
	_ "embed"
	"io"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/pkg/errors"

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
	}
	NFTContent interface {
		io.Closer
		HealthCheck(ctx context.Context) error
		Process(ctx context.Context, events model.Events) error
		GetNFTCollectionItemMetadata(ctx context.Context, nftContentType, contentAddress string) (*NFTResponse, *NFTCollectionMetadata, error)
		GetNFTCollectionMetadata(ctx context.Context, masterPubkey string) (*NFTResponse, *NFTCollectionMetadata, error)
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
	}
)

var (
	ErrForbiddenContent     = errors.New("forbidden content")
	ErrNotFound             = errors.New("not found")
	ErrOnBehalfAccessDenied = model.ErrOnBehalfAccessDenied
)

const (
	applicationYamlKey = "nft-content"

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
		NFTContentTypeUser:    "https://example.com/images/nft-image-user.png",
		NFTContentTypeAccount: "https://example.com/images/nft-image-account.png",
		NFTContentTypeVideo:   "https://example.com/images/nft-image-video.png",
		NFTContentTypeStory:   "https://example.com/images/nft-image-story.png",
		NFTContentTypePost:    "https://example.com/images/nft-image-post.png",
		NFTContentTypeArticle: "https://example.com/images/nft-image-article.png",
	}
)

type (
	nftContent struct {
		db            *storage.DB
		walletFetcher OwnerAddressFetcher
		config        *Config
	}
)
