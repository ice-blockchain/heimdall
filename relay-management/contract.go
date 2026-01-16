// SPDX-License-Identifier: ice License 1.0

package relaymanagement

import (
	"context"
	_ "embed"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"
	"github.com/puzpuzpuz/xsync/v4"
	"golang.org/x/sync/singleflight"

	"github.com/ice-blockchain/subzero/server/http/nip11"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

type (
	Relays interface {
		GetAllIONConnectRelays(ctx context.Context, requestedRelay *url.URL) ([]*UserAssignedRelay, error)
		IONConnectRelaysForUser(ctx context.Context, userId string) ([]*UserAssignedRelay, error)
	}
	UserAssignedRelay struct {
		URL  string `json:"url"`
		Type string `json:"type,omitempty"`
	}
	IonConnectClient interface {
		GetPost(ctx context.Context, relayUrl string, authorMasterKey, eventAddress string) (*PostPreview, error)
		SetKeyPair(kp interface{ PrivKey() string })
	}
	UserAssignedRelays []*UserAssignedRelay
	RelaysSyncer       interface {
		CheckRelayStatus(ctx context.Context) error
	}
	CommunityPostAuthor struct {
		Name        string `json:"name" example:"mahmutalijahad"`
		DisplayName string `json:"displayName" example:"Mahmut Ali Jahad"`
		Avatar      string `json:"avatar" example:"https://example.com/something.webp"`
		Verified    bool   `json:"verified" example:"true"`
	}
	PostMedia struct {
		Thumbnail *string `json:"thumbnail,omitempty" example:"https://example.com/image-preview.jpg"`
		URL       string  `json:"url" example:"https://example.com/image.jpg"`
		Type      string  `json:"type" example:"video"`
	}
	PostPreview struct {
		CreatedAt          *time.Time          `json:"createdAt" example:"2022-01-03T16:20:52.156534Z"`
		Media              []PostMedia         `json:"media,omitempty"`
		Author             CommunityPostAuthor `json:"author"`
		Type               string              `json:"type" example:"post"`
		Comments           int                 `json:"comments" example:"12"`
		Reposts            int                 `json:"reposts" example:"442"`
		Likes              int                 `json:"likes" example:"12000"`
		Content            string              `json:"content" example:"Something something https://example.com/someImage.webp https://example.com/someVideo.mp4 #online+"`
		OnlinePlusDeeplink string              `json:"onlinePlusDeeplink" example:"online.app://some/path/to/0xD76b5c2A23ef78368d8E34288B5b65D616B746aE"`
	}
)

var (
	ErrNoRelays = errors.Errorf("no relays")
)

var (
	//go:embed DDL.sql
	ddl string
)

const (
	applicationYamlKey = "relay-management"
)

type (
	relaysRepository struct {
		db       *storage.DB
		shutdown func() error
	}
	relaysSyncer struct {
		db       *storage.DB
		shutdown func() error
	}

	ionConnectRelays struct {
		IONConnectRelays UserAssignedRelays `db:"ion_connect_relays"`
	}
	nip11Result struct {
		url   string
		nip11 *nip11.RelayInformationDocument
		err   error
	}

	ionConnectClient struct {
		authPrivateKey   string
		connections      *xsync.Map[string, *relayConn]
		connSingleFlight singleflight.Group
	}
	relayConn struct {
		relay  *nostr.Relay
		usages atomic.Int64
	}
)
