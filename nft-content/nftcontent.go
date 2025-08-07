// SPDX-License-Identifier: ice License 1.0

package nftcontent

import (
	"context"
	"fmt"
	"net/url"
	"slices"

	"github.com/goccy/go-json"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func New(ctx context.Context) NFTContent {
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)

	var cfg Config
	config.MustLoadFromKey(applicationYamlKey, &cfg)

	return &nftContent{
		db:     db,
		config: &cfg,
	}
}

func (n *nftContent) Process(ctx context.Context, events model.Events) error {
	eventAttestation, eventProfileMetadata, contentEvent := n.parseEventsByKind(events)
	if err := n.validateAttestation(eventAttestation, events); err != nil {
		return errors.Wrap(err, "event validation failed")
	}
	contentType := getNFTContentType(contentEvent)
	if contentType == NFTContentTypeAccount {
		return errors.Wrap(n.insertNFTContentForAccountType(ctx, contentEvent), "failed to insert nft content for account type")
	}
	if err := n.insertNFTContent(ctx, contentEvent, eventProfileMetadata, contentType); err != nil {
		return errors.Wrapf(err, "database insertion failed for event: %s", contentEvent.ID)
	}

	return nil
}

func (n *nftContent) GetNFTCollectionMetadata(ctx context.Context, nftContentType, contentAddress string) (*NFTResponse, *NFTCollectionMetadata, error) {
	metadata, err := n.getNFTCollectionMetadata(ctx, nftContentType, contentAddress)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get nft collection metadata")
	}
	htmlPreviewUri, _ := url.JoinPath(n.config.HTMLPreviewBaseURL, metadata.Type, metadata.ContentAddress, "html-preview")
	resp := &NFTResponse{
		HtmlPreviewUri: htmlPreviewUri,
		Image:          imageUrlMap[NFTContentType(nftContentType)],
	}

	if NFTContentType(nftContentType) == NFTContentTypeAccount {
		profileUri, _ := url.JoinPath(n.config.ProfileURIBaseURL, metadata.Type, metadata.ContentAddress, "html-preview")
		resp.Name = fmt.Sprintf("%s's ION Profile", metadata.Username)
		resp.Description = fmt.Sprintf("Official ION Account for %s.", metadata.Username)
		resp.Type = responseAccountType
		resp.AccountID = metadata.Username
		resp.ProfileUri = profileUri
		resp.DisplayName = metadata.DisplayName
		if metadata.Bio != nil && *metadata.Bio != "" {
			resp.Bio = *metadata.Bio
		}
	} else {
		resp.Name = nftResponseName
		resp.Description = nftResponseDescription
		contentUri, _ := url.JoinPath(n.config.ContentURIBaseURL, metadata.Type, metadata.ContentAddress, "html-preview")
		resp.Type = responseContentType
		resp.Category = []NFTContentType{metadata.Type}
		resp.ContentUri = contentUri
		resp.ContentType = contentTypeHtml
		resp.AuthorID = metadata.Username
	}

	return resp, metadata, nil
}

func (n *nftContent) getNFTCollectionMetadata(ctx context.Context, nftContentType, contentAddress string) (*NFTCollectionMetadata, error) {
	stmt := `SELECT 
				sp.username,
				sp.display_name,
				sp.bio,
				n.content_address,
				n.nft_collection_address,
				n.nft_collection_name,
				n.nft_collection_creator_address,
				n.master_pubkey,
				n.type,
				n.status
			FROM nft_content n
			INNER JOIN social_profiles sp ON n.master_pubkey = sp.master_pubkey 
			WHERE n.content_address = $1 AND n.type = $2::nft_content_type AND n.status = 'completed';`
	row, err := storage.Get[NFTCollectionMetadata](ctx, n.db, stmt, contentAddress, string(nftContentType))
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return nil, errors.Wrap(ErrNotFound, "nft collection metadata not found")
		}

		return nil, errors.Wrap(err, "failed to get nft collection metadata")
	}

	return row, nil
}

func (n *nftContent) parseEventsByKind(events model.Events) (eventAttestation, eventProfileMetadata, contentEvent *model.Event) {
	contentEventIndex := slices.IndexFunc(events, func(event *model.Event) bool {
		return event.Kind == nostr.KindTextNote || event.Kind == model.CustomIONKindEditableTextNote || event.Kind == nostr.KindArticle
	})
	if contentEventIndex != -1 {
		contentEvent = events[contentEventIndex]
	}
	eventProfileMetadataIndex := slices.IndexFunc(events, func(event *model.Event) bool {
		return event.Kind == nostr.KindProfileMetadata
	})
	if eventProfileMetadataIndex != -1 {
		if contentEvent == nil {
			contentEvent = events[eventProfileMetadataIndex]
		} else {
			eventProfileMetadata = events[eventProfileMetadataIndex]
		}
	}
	attestationEventIndex := slices.IndexFunc(events, func(event *model.Event) bool {
		return event.Kind == model.CustomIONKindAttestation
	})
	if attestationEventIndex != -1 {
		eventAttestation = events[attestationEventIndex]
	}

	return eventAttestation, eventProfileMetadata, contentEvent
}

func (n *nftContent) validateAttestation(eventAttestation *model.Event, events model.Events) error {
	now := nostr.Now()
	for _, event := range events {
		if event.Kind == model.CustomIONKindAttestation {
			continue
		}
		if allowed, err := model.OnBehalfIsAccessAllowed(eventAttestation.Tags, event.PubKey, event.Kind, now); err != nil {
			return errors.Wrap(err, "failed to check if attestation event allows other event")
		} else if !allowed {
			return errors.Wrap(ErrOnBehalfAccessDenied, "attestation event does not allow the other event")
		}
	}

	return nil
}

func (n *nftContent) insertNFTContent(ctx context.Context, contentEvent *model.Event, eventProfileMetadata *model.Event, contentType NFTContentType) error {
	accountRecord, err := n.getAccountTypeRecord(ctx, contentEvent.GetMasterPublicKey())
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return errors.Wrap(ErrNotFound, "account type record not found")
		}

		return errors.Wrap(err, "failed to get account type record")
	}
	var profileContent model.ProfileMetadataContent
	if err := json.Unmarshal([]byte(eventProfileMetadata.Content), &profileContent); err != nil {
		return errors.Wrap(err, "failed to unmarshal profile metadata content")
	}
	if len(profileContent.IONContentNFTCollections) == 0 {
		return errors.Wrap(ErrForbiddenContent, "no nft collections found in profile metadata")
	}
	if collection, exists := profileContent.IONContentNFTCollections[model.IONContentNFTCollectionName(accountRecord.NFTCollectionName)]; !exists {
		return errors.Wrap(ErrForbiddenContent, "ion collection not found in profile metadata")
	} else if collection.Address != accountRecord.NFTCollectionAddress || collection.CreatedBy != accountRecord.NFTCollectionCreatorAddress {
		return errors.Wrap(ErrForbiddenContent, "ion collection does not match the account type record")
	}

	return errors.Wrap(n.insertNFTContentForContentType(ctx, contentEvent, accountRecord, contentType), "failed to insert nft content for content type")
}

func (n *nftContent) getAccountTypeRecord(ctx context.Context, masterPubKey string) (*NFTCollectionMetadata, error) {
	stmt := `SELECT * FROM nft_content 
			 WHERE content_address = $1 AND type = 'account'::nft_content_type AND status = 'completed';`
	row, err := storage.Get[NFTCollectionMetadata](ctx, n.db, stmt, masterPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get account type record")
	}

	return row, nil
}

func (n *nftContent) insertNFTContentForAccountType(ctx context.Context, contentEvent *model.Event) error {
	stmt := `INSERT INTO nft_content (content_address, master_pubkey, type) 
				 VALUES ($1, $1, 'account'::nft_content_type), 
				 		($1, $1, 'story'::nft_content_type)
				 ON CONFLICT (content_address, type) DO NOTHING;`
	args := []interface{}{contentEvent.GetMasterPublicKey()}
	_, err := storage.Exec(ctx, n.db, stmt, args...)
	if err != nil {
		if storage.IsErr(err, storage.ErrRelationNotFound) {
			return errors.Wrap(ErrNotFound, "user not found")
		}

		return errors.Wrap(err, "failed to insert nft content for account")
	}

	return nil
}

func (n *nftContent) insertNFTContentForContentType(ctx context.Context, contentEvent *model.Event, accountRecord *NFTCollectionMetadata, contentType NFTContentType) error {
	stmt := `INSERT INTO nft_content (content_address, nft_collection_address, nft_collection_name, nft_collection_creator_address, master_pubkey, type)
		 VALUES ($1, $2, $3, $4, $5, $6::nft_content_type) 
		 ON CONFLICT (content_address, type) DO NOTHING;`
	masterPubKey := contentEvent.GetMasterPublicKey()
	contentAddress := contentEvent.Address()
	args := []interface{}{contentAddress, accountRecord.NFTCollectionAddress, accountRecord.NFTCollectionName, accountRecord.NFTCollectionCreatorAddress, masterPubKey, string(contentType)}
	_, err := storage.Exec(ctx, n.db, stmt, args...)
	if err != nil {
		if storage.IsErr(err, storage.ErrRelationNotFound) {
			return errors.Wrap(ErrNotFound, "user not found")
		}

		return errors.Wrap(err, "failed to insert nft content for content")
	}

	return nil
}

func getNFTContentType(contentEvent *model.Event) NFTContentType {
	switch contentEvent.Kind {
	case nostr.KindProfileMetadata:
		return NFTContentTypeAccount
	case nostr.KindTextNote, model.CustomIONKindEditableTextNote:
		if contentEvent.IsStory() {
			return NFTContentTypeStory
		}
		if contentEvent.HasVideoIMeta() {
			return NFTContentTypeVideo
		}

		return NFTContentTypePost
	case nostr.KindArticle:
		return NFTContentTypeArticle
	default:
		panic("unknown content type")
	}
}

func (n *nftContent) Close() error {
	return n.db.Close()
}

func (n *nftContent) HealthCheck(ctx context.Context) error {
	return errors.Wrap(n.db.Ping(ctx), "failed to ping database")
}
