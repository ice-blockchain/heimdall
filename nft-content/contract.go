// SPDX-License-Identifier: ice License 1.0

package nftcontent

import (
	"context"
	_ "embed"
	"io"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

const (
	NFTContentTypeAccount NFTContentType = "account"
	NFTContentTypePost    NFTContentType = "post"
	NFTContentTypeArticle NFTContentType = "article"
	NFTContentTypeVideo   NFTContentType = "video"
	NFTContentTypeStory   NFTContentType = "story"

	NFTContentStatusNew       NFTContentStatus = "new"
	NFTContentStatusPending   NFTContentStatus = "pending"
	NFTContentStatusCompleted NFTContentStatus = "completed"
)

type (
	NFTContentStatus = string
	NFTContentType   = string
	NFTContent       interface {
		io.Closer
		HealthCheck(ctx context.Context) error
		Process(ctx context.Context, events model.Events) error
		GetNFTCollectionMetadataAccount(ctx context.Context, nftContentType, contentAddress string) (*NFTResponseAccount, *NFTCollectionMetadata, error)
		GetNFTCollectionMetadataContent(ctx context.Context, nftContentType, contentAddress string) (*NFTResponseContent, *NFTCollectionMetadata, error)
	}
	NFTCollectionMetadata struct {
		Username                    string           `db:"username"`
		DisplayName                 string           `db:"display_name"`
		ContentAddress              string           `db:"content_address"`
		NFTCollectionAddress        string           `db:"nft_collection_address"`
		NFTCollectionName           string           `db:"nft_collection_name"`
		NFTCollectionCreatorAddress string           `db:"nft_collection_creator_address"`
		MasterPubKey                string           `db:"master_pubkey"`
		Type                        NFTContentType   `db:"type"`
		Status                      NFTContentStatus `db:"status"`
		Bio                         *string          `db:"bio"`
	}
	NFTResponseAccount struct {
		Type           NFTContentType `json:"type,omitempty" example:"Account"`
		Name           string         `json:"name,omitempty" example:"John Doe's ION profile"`
		Description    string         `json:"description,omitempty" example:"Oficial ION Account for John Doe"`
		Image          string         `json:"image,omitempty" example:"https://example.com/image.png"`
		HtmlPreviewUri string         `json:"html_preview_uri,omitempty" example:"https://example.com/html_preview.html"`
		AccountID      string         `json:"account_id,omitempty" example:"johndoe"`
		ProfileUri     string         `json:"profile_uri,omitempty" example:"https://someOtherEnvBasedBaseUrl/{nft_content_type}/{content_address}"`
		DisplayName    string         `json:"display_name,omitempty" example:"John Doe"`
		Bio            string         `json:"bio,omitempty" example:"Oficial ION Account for John Doe"`
	}
	NFTResponseContent struct {
		Type           NFTContentType   `json:"type,omitempty" example:"[Video, Post]"`
		Name           string           `json:"name,omitempty" example:"John Doe's ION profile"`
		Description    string           `json:"description,omitempty" example:"Oficial ION Account for John Doe"`
		Image          string           `json:"image,omitempty" example:"https://example.com/image.png"`
		HtmlPreviewUri string           `json:"html_preview_uri,omitempty" example:"https://example.com/html_preview.html"`
		ContentUri     string           `json:"content_uri,omitempty" example:"https://someOtherEnvBasedBaseUrl/{nft_content_type}/{content_address}"`
		ContentType    string           `json:"content_type,omitempty" example:"text/html"`
		AuthorID       string           `json:"author_id,omitempty" example:"john doe"`
		Category       []NFTContentType `json:"category,omitempty" example:"Social"`
		Tags           []string         `json:"tags"`
		Attributes     []string         `json:"attributes"`
	}

	Config struct {
		EnvBasedUrl string `yaml:"envBasedUrl"`
	}
)

var (
	ErrForbiddenContent     = errors.New("forbidden content")
	ErrNotFound             = errors.New("not found")
	ErrOnBehalfAccessDenied = model.ErrOnBehalfAccessDenied
)

const (
	applicationYamlKey = "nft-content"

	nftResponseName        string = "Heimdall Identity"
	nftResponseDescription string = "Heimdall Identity"

	contentTypeHtml string = "text/html"

	responseContentType string = "Content"
	responseAccountType string = "Account"
)

var (
	//go:embed DDL.sql
	ddl string

	imageUrlMap = map[NFTContentType]string{
		NFTContentTypeAccount: "https://ice.io/images/nft-image-account.png",
		NFTContentTypeVideo:   "https://ice.io/images/nft-image-video.png",
		NFTContentTypeStory:   "https://ice.io/images/nft-image-story.png",
		NFTContentTypePost:    "https://ice.io/images/nft-image-post.png",
		NFTContentTypeArticle: "https://ice.io/images/nft-image-article.png",
	}
)

type (
	nftContent struct {
		db     *storage.DB
		config *Config
	}
)
