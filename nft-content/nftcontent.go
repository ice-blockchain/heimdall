// SPDX-License-Identifier: ice License 1.0

package nftcontent

import (
	"context"
	"fmt"
	"strings"

	"github.com/goccy/go-json"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func New(ctx context.Context) NFTContent {
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)

	return &nftContent{db: db}
}

func (n *nftContent) Process(ctx context.Context, events []*model.Event) error {
	eventAttestation, eventProfileMetadata, contentEvent := n.parseEventsByKind(events)
	if err := n.validateAttestation(eventAttestation, events); err != nil {
		return errors.Wrap(err, "event validation failed")
	}
	var profileContent model.ProfileMetadataContent
	if err := json.Unmarshal([]byte(eventProfileMetadata.Content), &profileContent); err != nil {
		return errors.Wrap(err, "failed to unmarshal profile metadata content")
	}
	contentType := getNFTContentType(&profileContent, contentEvent)
	if contentType != NFTContentTypeAccount && len(profileContent.IONContentNFTCollections) == 0 {
		return errors.Wrap(ErrForbiddenContent, "no nft collections found in profile metadata")
	}
	if err := n.insertNFTContent(ctx, eventAttestation, contentEvent, &profileContent, contentType); err != nil {
		contentEventID := ""
		if contentEvent != nil {
			contentEventID = contentEvent.ID
		}
		return errors.Wrapf(err, "database insertion failed for events: %s, %s, %s", eventAttestation.ID, eventProfileMetadata.ID, contentEventID)
	}

	return nil
}

func (n *nftContent) parseEventsByKind(events []*model.Event) (eventAttestation, eventProfileMetadata, contentEvent *model.Event) {
	for _, event := range events {
		switch event.Kind {
		case nostr.KindProfileMetadata:
			eventProfileMetadata = event
		case model.CustomIONKindAttestation:
			eventAttestation = event
		case nostr.KindTextNote, model.CustomIONKindEditableTextNote, nostr.KindArticle:
			contentEvent = event
		}
	}

	return eventAttestation, eventProfileMetadata, contentEvent
}

func (n *nftContent) validateAttestation(eventAttestation *model.Event, events []*model.Event) error {
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

func (n *nftContent) insertNFTContent(ctx context.Context, eventAttestation *model.Event, contentEvent *model.Event, profileContent *model.ProfileMetadataContent, contentType NFTContentType) error {
	if contentType == NFTContentTypeAccount {
		return errors.Wrap(n.insertNFTContentForAccount(ctx, eventAttestation, contentType), "failed to insert nft content for account")
	}

	return errors.Wrap(n.insertNFTContentForContent(ctx, contentEvent, profileContent, contentType), "failed to insert nft content for content")
}

func (n *nftContent) insertNFTContentForAccount(ctx context.Context, eventAttestation *model.Event, contentType NFTContentType) error {
	const numFields = 3

	stmt := `INSERT INTO nft_content (content_address, master_pubkey, type)
			SELECT * FROM (VALUES `

	masterPubKey := eventAttestation.GetMasterPublicKey()
	contentAddress := masterPubKey

	args := make([]any, 0, numFields)
	args = append(args, contentAddress, masterPubKey, string(contentType))

	stmt += `($1, $2, $3::nft_content_type)
			) AS v(content_address, master_pubkey, type) 
			WHERE EXISTS(SELECT 1 FROM users WHERE master_pubkey = v.master_pubkey) 
			ON CONFLICT (content_address) DO NOTHING;`

	_, err := storage.Exec(ctx, n.db, stmt, args...)
	if err != nil {
		return errors.Wrap(err, "failed to insert nft content for account")
	}

	return nil
}

func (n *nftContent) insertNFTContentForContent(ctx context.Context, contentEvent *model.Event, profileContent *model.ProfileMetadataContent, contentType NFTContentType) error {
	if contentEvent == nil {
		return errors.New("contentEvent cannot be nil for non-account types")
	}

	const numFields = 5
	collectionsCount := len(profileContent.IONContentNFTCollections)
	stmt := `INSERT INTO nft_content (content_address, nft_collection_address, nft_collection_creator_address, master_pubkey, type)
			 SELECT * FROM (VALUES `

	masterPubKey := contentEvent.GetMasterPublicKey()
	contentAddress := contentEvent.Address()

	args := make([]any, 0, collectionsCount*numFields)
	placeholders := make([]string, 0, collectionsCount)

	ix := 0
	for _, collection := range profileContent.IONContentNFTCollections {
		baseIdx := ix * numFields
		args = append(args, contentAddress, collection.Address, collection.CreatedBy, masterPubKey, string(contentType))
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d::nft_content_type)", baseIdx+1, baseIdx+2, baseIdx+3, baseIdx+4, baseIdx+5))
		ix++
	}

	stmt += strings.Join(placeholders, ", ")
	stmt += `) AS v(content_address, nft_collection_address, nft_collection_creator_address, master_pubkey, type) 
			WHERE EXISTS(SELECT 1 FROM users WHERE master_pubkey = v.master_pubkey) 
			ON CONFLICT (content_address) DO NOTHING;`

	_, err := storage.Exec(ctx, n.db, stmt, args...)
	if err != nil {
		return errors.Wrap(err, "failed to insert nft content for content")
	}

	return nil
}

func getNFTContentType(profileContent *model.ProfileMetadataContent, contentEvent *model.Event) NFTContentType {
	if isAccountType, err := isAccountType(*profileContent, contentEvent); err != nil {
		return NFTContentTypePost
	} else if isAccountType {
		return NFTContentTypeAccount
	}
	switch contentEvent.Kind {
	case nostr.KindTextNote, model.CustomIONKindEditableTextNote:
		if hasVideoImeta(contentEvent) {
			return NFTContentTypeVideo
		}

		return NFTContentTypePost
	case nostr.KindArticle:
		return NFTContentTypeArticle
	default:
		return NFTContentTypePost
	}
}

func isAccountType(profileContent model.ProfileMetadataContent, contentEvent *model.Event) (bool, error) {
	return contentEvent == nil && len(profileContent.IONContentNFTCollections) == 0, nil
}

func hasVideoImeta(event *model.Event) bool {
	imetaTags := event.GetTags("imeta")
	for _, imetaTag := range imetaTags {
		values, err := model.ParseIMeta(imetaTag)
		if err != nil {
			continue
		}
		if mimeType, exists := values["m"]; exists {
			if strings.HasPrefix(mimeType, "video") {
				return true
			}
		}
	}

	return false
}

func (n *nftContent) Close() error {
	return n.db.Close()
}

func (n *nftContent) HealthCheck(ctx context.Context) error {
	return errors.Wrap(n.db.Ping(ctx), "failed to ping database")
}
