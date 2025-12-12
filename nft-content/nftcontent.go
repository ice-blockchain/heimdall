// SPDX-License-Identifier: ice License 1.0

package nftcontent

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/goccy/go-json"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"
	"github.com/xssnick/tonutils-go/address"

	indexer "github.com/ice-blockchain/heimdall/ion-indexer"
	tokenanalytics "github.com/ice-blockchain/heimdall/token-analytics"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/config"
	storage "github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func New(ctx context.Context, walletFetcher OwnerAddressFetcher, indexer indexer.Indexer, userRepo tokenanalytics.UserRepository) NFTContent {
	db := storage.MustConnect(ctx, applicationYamlKey, storage.NewStringDDL(ddl))

	var cfg Config
	config.MustLoadFromKey(applicationYamlKey, &cfg)
	nft := &nftContent{
		db:             db,
		walletFetcher:  walletFetcher,
		config:         &cfg,
		indexer:        indexer,
		userRepository: userRepo,
	}
	walletFetcher.SetProviderForUnsupportedNFTs(nft.indexer)
	return nft
}

func (n *nftContent) ListNFTs(ctx context.Context, walletAddr string, paginationToken string, limit uint64) ([]WalletNFT, *string, error) {
	return n.indexer.ListNFTs(ctx, walletAddr, paginationToken, limit)
}

func (n *nftContent) Process(ctx context.Context, events model.Events) error {
	eventAttestation, eventProfileMetadata, contentEvent := n.parseEventsByKind(events)
	if err := n.validateAttestation(eventAttestation, events); err != nil {
		return errors.Wrap(err, "event validation failed")
	}
	contentType := getNFTContentType(contentEvent)
	if contentType == NFTContentTypeAccount {
		var profileContent model.ProfileMetadataContent
		if err := json.Unmarshal([]byte(contentEvent.Content), &profileContent); err != nil {
			return errors.Wrap(err, "failed to unmarshal profile metadata content")
		}
		hasNFTCollections := len(profileContent.IONContentNFTCollections) > 0
		userID, nftRecordExists, err := n.checkNFTRecordExists(ctx, contentEvent.GetMasterPublicKey())
		if err != nil {
			return errors.Wrap(err, "failed to check nft record existence")
		}
		if hasNFTCollections && !nftRecordExists {
			owner, err := n.getOwnerWalletAddress(ctx, contentEvent)
			if err != nil {
				return errors.Wrapf(err, "failed to detect owner of nft items for profile %v", contentEvent.GetMasterPublicKey())
			}
			return errors.Wrap(n.insertNFTContentForAccountType(ctx, contentEvent, owner), "failed to insert nft content for account type")
		}
		if err := n.updateUserBSCAddress(ctx, contentEvent, userID); err != nil {
			return errors.Wrap(err, "failed to update user bsc address for account type")
		}

		return nil
	}
	if err := n.insertNFTContent(ctx, contentEvent, eventProfileMetadata, contentType); err != nil {
		return errors.Wrapf(err, "database insertion failed for event: %s", contentEvent.ID)
	}

	return nil
}

func (n *nftContent) updateUserBSCAddress(ctx context.Context, profileEvent *model.Event, userID string) error {
	var profileContent model.ProfileMetadataContent
	if err := json.Unmarshal([]byte(profileEvent.Content), &profileContent); err != nil {
		return errors.Wrap(err, "failed to unmarshal profile metadata content")
	}
	bscAddress := ""
	for network, walletAddr := range profileContent.Wallets {
		if strings.EqualFold(network, "bsc") || strings.EqualFold(network, "bsctestnet") {
			bscAddress = walletAddr

			break
		}
	}
	masterPubkey := profileEvent.GetMasterPublicKey()
	if bscAddress == "" {
		user, err := n.userRepository.GetUser(ctx, masterPubkey)
		if err != nil {
			return errors.Wrap(err, "failed to get user from token-analytics")
		}
		if user == nil {
			return nil
		}
	}
	displayName := profileContent.DisplayName
	avatar := profileContent.Picture
	if bscAddress == "" {
		displayName = "Hidden"
		avatar = ""
	}

	err := n.userRepository.UpsertUser(
		ctx,
		userID,
		masterPubkey,
		bscAddress,
		profileContent.Name,
		displayName,
		avatar,
		nil,
		nil,
	)
	if err != nil {
		return errors.Wrap(err, "failed to update user BSC address in token-analytics")
	}

	return nil
}

func (n *nftContent) GetNFTCollectionMetadata(ctx context.Context, masterPubkey string) (*NFTResponse, *NFTCollectionMetadata, error) {
	stmt := `SELECT 
				sp.username,
				n.nft_collection_address,
				n.nft_collection_name,
				n.nft_collection_creator_address
			 FROM nft_content n
					INNER JOIN social_profiles sp 
					        ON n.master_pubkey = sp.master_pubkey 
			 WHERE n.content_address = $1 
			   AND n.type = 'account' 
			   AND n.status = 'completed';`
	row, err := storage.Get[struct {
		NFTCollectionMetadata
		Username string `db:"username"`
	}](ctx, n.db, stmt, masterPubkey)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return nil, nil, errors.Wrap(ErrNotFound, "root nft collection metadata not found")
		}

		return nil, nil, errors.Wrap(err, "failed to get root nft collection metadata")
	}

	return &NFTResponse{
			Name:        fmt.Sprintf("%s's Collection", row.Username),
			Description: fmt.Sprintf("A personal on-chain collection for @%s. All account, story, post, video, and article NFTs are stored here, permanently tied to the user's identity.", row.Username),
			Image:       imageUrlMap[NFTContentTypeUser],
			Symbol:      row.Username,
		},
		&row.NFTCollectionMetadata,
		nil
}

func (n *nftContent) GetNFTCollectionItemMetadata(ctx context.Context, nftContentType, contentAddress string) (*NFTResponse, *NFTCollectionMetadata, error) {
	metadata, err := n.getNFTCollectionItemMetadata(ctx, nftContentType, contentAddress)
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
		resp.Name = "Identity"
		resp.Description = fmt.Sprintf("The first NFT in @%s's collection. It proves their account registration and anchors their identity on-chain.", metadata.Username)
		resp.Type = responseAccountType
		resp.AccountID = metadata.Username
		resp.ProfileUri = profileUri
		resp.DisplayName = metadata.DisplayName
		if metadata.Bio != nil && *metadata.Bio != "" {
			resp.Bio = *metadata.Bio
		}
	} else {
		contentUri, _ := url.JoinPath(n.config.ContentURIBaseURL, metadata.Type, metadata.ContentAddress, "html-preview")
		resp.Type = responseContentType
		resp.Category = []NFTContentType{metadata.Type}
		resp.ContentUri = contentUri
		resp.ContentType = contentTypeHtml
		resp.AuthorID = metadata.Username

		switch NFTContentType(nftContentType) {
		case NFTContentTypeStory:
			resp.Name = "Stories"
			resp.Description = fmt.Sprintf("An NFT that contains all currently active stories shared by @%s. When stories expire, their content is no longer available, but the NFT remains, always reflecting the user's active stories at that moment.", metadata.Username)
		case NFTContentTypePost:
			resp.Name = "Post"
			resp.Description = fmt.Sprintf("An immutable record of @%s's post, preserved inside their personal collection.", metadata.Username)
		case NFTContentTypeVideo:
			resp.Name = "Video"
			resp.Description = fmt.Sprintf("An immutable record of @%s's video, stored forever in their collection.", metadata.Username)
		case NFTContentTypeArticle:
			resp.Name = "Article"
			resp.Description = fmt.Sprintf("An immutable record of @%s's article, recording their authorship permanently.", metadata.Username)
		default:
			resp.Name = nftResponseName
			resp.Description = nftResponseDescription
		}
	}

	return resp, &metadata.NFTCollectionMetadata, nil
}

func (n *nftContent) getNFTCollectionItemMetadata(ctx context.Context, nftContentType, contentAddress string) (*NFTCollectionItemMetadata, error) {
	stmt := `SELECT 
				sp.username,
				sp.display_name,
				sp.bio,
				n.content_address,
				n.nft_collection_address,
				n.nft_collection_name,
				n.nft_collection_creator_address,
				n.nft_item_address,
				n.master_pubkey,
				n.type,
				n.status,
				n.created_at
			FROM nft_content n
			INNER JOIN social_profiles sp ON n.master_pubkey = sp.master_pubkey 
			WHERE n.content_address = $1 AND n.type = $2::nft_content_type AND n.status = 'completed';`
	row, err := storage.Get[NFTCollectionItemMetadata](ctx, n.db, stmt, contentAddress, string(nftContentType))
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

func (n *nftContent) checkNFTRecordExists(ctx context.Context, masterPubKey string) (userID string, nftExists bool, err error) {
	stmt := `SELECT u.id, nc.content_address
			 FROM users u
			 LEFT JOIN nft_content nc ON nc.master_pubkey = u.master_pubkey 
			                          AND nc.type = 'account'::nft_content_type
			 WHERE u.master_pubkey = $1`
	type row struct {
		UserID         string  `db:"id"`
		ContentAddress *string `db:"content_address"`
	}
	result, err := storage.Get[row](ctx, n.db, stmt, masterPubKey)
	if err != nil {
		return "", false, errors.Wrap(err, "failed to check nft record existence")
	}

	return result.UserID, result.ContentAddress != nil, nil
}

func (n *nftContent) getAccountTypeRecord(ctx context.Context, masterPubKey string) (*NFTCollectionItemMetadata, error) {
	stmt := `SELECT 
				content_address,
				nft_collection_address,
				nft_collection_name,
				nft_collection_creator_address,
				nft_item_address,
				master_pubkey,
				owner,
				type,
				status,
				created_at
			 FROM nft_content 
			 WHERE content_address = $1 AND type = 'account'::nft_content_type AND status = 'completed';`
	row, err := storage.Get[NFTCollectionItemMetadata](ctx, n.db, stmt, masterPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get account type record")
	}

	return row, nil
}

func (n *nftContent) insertNFTContentForAccountType(ctx context.Context, contentEvent *model.Event, owner string) error {
	stmt := `INSERT INTO nft_content (content_address, master_pubkey, owner, type) 
				 VALUES ($1, $1,$2, 'account'::nft_content_type), 
				 		($1, $1,$2, 'story'::nft_content_type)
				 ON CONFLICT (content_address, type) DO NOTHING;`
	args := []interface{}{contentEvent.GetMasterPublicKey(), owner}
	_, err := storage.Exec(ctx, n.db, stmt, args...)
	if err != nil {
		if storage.IsErr(err, storage.ErrRelationNotFound) {
			return errors.Wrap(ErrNotFound, "user not found")
		}

		return errors.Wrap(err, "failed to insert nft content for account")
	}

	return nil
}

func (n *nftContent) insertNFTContentForContentType(ctx context.Context, contentEvent *model.Event, accountRecord *NFTCollectionItemMetadata, contentType NFTContentType) error {
	stmt := `INSERT INTO nft_content (content_address, nft_collection_address, nft_collection_name, nft_collection_creator_address, master_pubkey, owner, type)
		 VALUES ($1, $2, $3, $4, $5, $7, $6::nft_content_type) 
		 ON CONFLICT (content_address, type) DO NOTHING;`
	masterPubKey := contentEvent.GetMasterPublicKey()
	contentAddress := contentEvent.Address()
	args := []interface{}{contentAddress, accountRecord.NFTCollectionAddress, accountRecord.NFTCollectionName, accountRecord.NFTCollectionCreatorAddress, masterPubKey, string(contentType), accountRecord.Owner}
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

func (n *nftContent) getOwnerWalletAddress(ctx context.Context, event *model.Event) (string, error) {
	var profileContent model.ProfileMetadataContent
	if err := json.Unmarshal([]byte(event.Content), &profileContent); err != nil {
		return "", errors.Wrap(err, "failed to unmarshal profile metadata content")
	}
	mainWalletAddr := ""
	for network, walletAddr := range profileContent.Wallets {
		if network == defaultWalletNetworkMainNet || network == defaultWalletNetworkTestNet {
			mainWalletAddr = walletAddr
			break
		}
	}
	if mainWalletAddr == "" {
		wallet, err := n.walletFetcher.FetchMainWallet(ctx, event.GetMasterPublicKey())
		if err != nil {
			return "", errors.Wrapf(err, "failed to fetch main wallet for master key %v", event.GetMasterPublicKey())
		}
		mainWalletAddr = wallet["address"].(string)
	}
	addr, err := address.ParseAddr(mainWalletAddr)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse wallet address %q for master key %v", mainWalletAddr, event.GetMasterPublicKey())
	}
	return addr.StringRaw(), nil
}
