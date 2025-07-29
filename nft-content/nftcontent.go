// SPDX-License-Identifier: ice License 1.0

package nftcontent

import (
	"context"
	"slices"

	"github.com/goccy/go-json"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/subzero/validation"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func New(ctx context.Context) NFTContent {
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)

	return &nftContent{db: db}
}

func (n *nftContent) Process(ctx context.Context, events model.Events) error {
	eventAttestation, eventProfileMetadata, contentEvent := n.parseEventsByKind(events)
	if err := n.validateAttestation(eventAttestation, events); err != nil {
		return errors.Wrap(err, "event validation failed")
	}
	var profileContent model.ProfileMetadataContent
	if eventProfileMetadata != nil {
		if err := json.Unmarshal([]byte(eventProfileMetadata.Content), &profileContent); err != nil {
			return errors.Wrap(err, "failed to unmarshal profile metadata content")
		}
	}
	contentType := getNFTContentType(contentEvent)
	if contentType != NFTContentTypeAccount && eventProfileMetadata != nil && len(profileContent.IONContentNFTCollections) == 0 {
		return errors.Wrap(ErrForbiddenContent, "no nft collections found in profile metadata")
	}
	if err := n.insertNFTContent(ctx, contentEvent, &profileContent, contentType); err != nil {
		return errors.Wrapf(err, "database insertion failed for event: %s", contentEvent.ID)
	}

	return nil
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

func (n *nftContent) insertNFTContent(ctx context.Context, contentEvent *model.Event, profileContent *model.ProfileMetadataContent, contentType NFTContentType) error {
	if contentType == NFTContentTypeAccount {
		return errors.Wrap(n.insertNFTContentForAccountType(ctx, contentEvent), "failed to insert nft content for account type")
	}
	if contentEvent == nil {
		return errors.Wrap(ErrForbiddenContent, "content event is nil for non-account types")
	}
	ionCollection, exists := profileContent.IONContentNFTCollections[validation.IONNFTCollectionName]
	if !exists {
		return errors.Wrap(ErrForbiddenContent, "ion collection not found in profile metadata")
	}

	return errors.Wrap(n.insertNFTContentForContentType(ctx, contentEvent, &ionCollection, contentType), "failed to insert nft content for content type")
}

func (n *nftContent) insertNFTContentForAccountType(ctx context.Context, contentEvent *model.Event) error {
	stmt := `INSERT INTO nft_content (content_address, master_pubkey, type) VALUES ($1, $1, $2::nft_content_type) 
			 			ON CONFLICT (content_address)
			 			DO NOTHING;`
	_, err := storage.Exec(ctx, n.db, stmt, contentEvent.GetMasterPublicKey(), NFTContentTypeAccount)
	if err != nil {
		if storage.IsErr(err, storage.ErrRelationNotFound) {
			return errors.Wrap(ErrNotFound, "user not found")
		}

		return errors.Wrap(err, "failed to insert nft content for account")
	}

	return nil
}

func (n *nftContent) insertNFTContentForContentType(ctx context.Context, contentEvent *model.Event, ionCollection *model.IONContentNFTCollectionMetadata, contentType NFTContentType) error {
	stmt := `INSERT INTO nft_content (content_address, nft_collection_address, nft_collection_creator_address, master_pubkey, type)
			 VALUES ($1, $2, $3, $4, $5::nft_content_type) 
			 ON CONFLICT (content_address) DO NOTHING;`
	masterPubKey := contentEvent.GetMasterPublicKey()
	contentAddress := contentEvent.Address()
	_, err := storage.Exec(ctx, n.db, stmt, contentAddress, ionCollection.Address, ionCollection.CreatedBy, masterPubKey, string(contentType))
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
