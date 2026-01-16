// SPDX-License-Identifier: ice License 1.0

package relaymanagement

import (
	"context"
	"crypto/tls"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/goccy/go-json"
	"github.com/nbd-wtf/go-nostr"
	"github.com/puzpuzpuz/xsync/v4"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/log"
)

func NewIonConnectClient() IonConnectClient {
	return &ionConnectClient{
		connections: xsync.NewMap[string, *relayConn](),
	}
}

func (c *ionConnectClient) SetKeyPair(kp interface{ PrivKey() string }) {
	c.authPrivateKey = kp.PrivKey()
}

func (c *ionConnectClient) acquireRelay(ctx context.Context, url string) (r *nostr.Relay, err error) {
	relayConnection, _ := c.connections.LoadOrCompute(url, func() (newValue *relayConn, cancel bool) {
		var rVal interface{}
		rVal, err, _ = c.connSingleFlight.Do(url, func() (interface{}, error) {
			return c.newRelay(ctx, url)
		})
		r = rVal.(*nostr.Relay)
		return &relayConn{relay: r}, false
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to relay %s", url)
	}
	r = relayConnection.relay
	relayConnection.usages.Add(1)
	return r, nil
}

func (c *ionConnectClient) freeRelay(url string) {
	relay, ok := c.connections.Load(url)
	if ok {
		if relay.usages.Add(-1) <= 0 {
			relay.relay.Close()
			c.connections.Delete(url)
		}
	}
}

func (c *ionConnectClient) newInitAuthEvent(url string) *model.Event {
	var ev model.Event

	ev.Kind = nostr.KindClientAuthentication
	ev.CreatedAt = nostr.Now()
	ev.Tags = model.Tags{
		{"challenge", "init"},
	}
	if err := ev.SignWithAlg(c.authPrivateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		log.Panic(errors.Wrapf(err, "failed to sign init auth event for relay %s", url))
	}

	return &ev
}

func (c *ionConnectClient) newRelay(ctx context.Context, url string) (*nostr.Relay, error) {
	relay := nostr.NewRelay(ctx, url, nostr.WithSignatureChecker(func(e *nostr.Event) bool {
		ev := model.Event{Event: *e}
		ok, err := ev.CheckSignature()
		return ok && err == nil
	}))

	err := relay.ConnectWithTLS(ctx, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, errors.Wrap(err, "relay connection failed")
	}

	err = relay.Publish(ctx, c.newInitAuthEvent(url).Event)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required:") {
			err = errors.Wrap(relay.Auth(ctx, func(event *nostr.Event) error {
				subZeroEvent := model.Event{Event: *event}
				subZeroEvent.Tags = append(subZeroEvent.Tags,
					model.Tag{"user-agent", runtime.GOOS + "/" + runtime.Version() + " heimdall-identity-io"},
				)
				if err := subZeroEvent.SignWithAlg(c.authPrivateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
					return err
				}
				*event = subZeroEvent.Event

				return nil
			}), "failed to authenticate to relay")

			if err == nil {
				return relay, nil // Authentication successful.
			}
		}

		relay.Close()
		return nil, errors.Wrapf(err, "failed to publish authentication event to %s", url)
	}

	return relay, nil
}

func (c *ionConnectClient) GetPost(ctx context.Context, relayUrl, eventAuthor, eventAddress string) (*PostPreview, error) {
	relay, err := c.acquireRelay(ctx, relayUrl)
	defer c.freeRelay(relayUrl)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to acquire relay connection %s", relayUrl)
	}
	events, err := queryEvents(ctx, relay, []nostr.Filter{c.getPostFilter(eventAuthor, eventAddress)}, nostr.WithDoNotCheckFilters())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query events from relay %s", relayUrl)
	}
	preview := &PostPreview{}
	for e := range events {
		ev := model.Event{nil, *e}
		switch ev.Kind {
		case nostr.KindProfileMetadata:
			kind0Data, err := c.extractProfileContentMetadata(ev.Content)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse author's metadata: %v", ev.Content)
			}
			preview.Author = CommunityPostAuthor{
				Name:        kind0Data.Name,
				DisplayName: kind0Data.DisplayName,
				Avatar:      kind0Data.Picture,
			}
		case nostr.KindBadgeAward:
			aTags := ev.Tags.GetAll([]string{"a"})
			for _, aTag := range aTags {
				if len(aTag) >= 2 {
					if aTag[1] == fmt.Sprintf("%d:%s:verified", nostr.KindBadgeDefinition, eventAuthor) {
						preview.Author.Verified = true
						break
					}
				}
			}
		case nostr.KindTextNote, model.CustomIONKindEditableTextNote, nostr.KindArticle:
			createdAt := ev.CreatedAt.Time()
			preview.CreatedAt = &createdAt
			preview.Content = ev.Content
			switch ev.Kind {
			case nostr.KindArticle:
				preview.Type = "article"
			default:
				if ev.HasVideoIMeta() {
					preview.Type = "video"
				}
				preview.Type = "post"
			}
			for _, imeta := range ev.Tags.GetAll([]string{"imeta"}) {
				media, err := model.ParseIMeta(imeta)
				if err != nil {
					return nil, errors.Wrapf(err, "failed to parse media tag %v", imeta)
				}
				preview.Media = append(preview.Media, c.convertMedia(media))
			}
		case model.KindJobNostrEventCount + 1000:
			requestPayload := ev.Tags.GetFirst([]string{"request"})
			var dvmReq model.Event
			if err = json.Unmarshal([]byte(requestPayload.Value()), &dvmReq); err != nil {
				return nil, errors.Wrapf(err, "failed to unmarshal dvm request %v", requestPayload)
			}
			if dvmReq.Kind == model.KindJobNostrEventCount {
				var reqKinds []struct {
					Kinds []int `json:"kinds"`
				}
				if err = json.Unmarshal([]byte(dvmReq.Content), &reqKinds); err != nil {
					return nil, errors.Wrapf(err, "failed to unmarshal dvm payload %v", dvmReq.Content)
				}
				if len(reqKinds) == 0 || len(reqKinds[0].Kinds) == 0 {
					return nil, errors.New("no kinds specified in dvm request")
				}
				kind := reqKinds[0].Kinds[0]
				counter, err := strconv.Atoi(ev.Content)
				if err != nil {
					var reactions map[string]int
					if err = json.Unmarshal([]byte(ev.Content), &reactions); err != nil {
						return nil, errors.Wrapf(err, "failed to unmarshal counter %v", ev.Content)
					}
					counter = reactions["+"]
				}
				switch kind {
				case nostr.KindGenericRepost, nostr.KindRepost:
					preview.Reposts = counter
				case model.CustomIONKindEditableTextNote, nostr.KindTextNote:
					preview.Comments = counter
				case nostr.KindReaction:
					preview.Likes = counter
				}
			}
		}
	}
	return preview, nil
}

func queryEvents(ctx context.Context, r *nostr.Relay, filters []model.Filter, opts ...nostr.SubscriptionOption) (<-chan *nostr.Event, error) {
	sub, err := r.Subscribe(ctx, filters, opts...)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			select {
			case <-sub.ClosedReason:
			case <-sub.EndOfStoredEvents:
			case <-ctx.Done():
			case <-r.Context().Done():
			}
			sub.Unsub()
			return
		}
	}()

	return sub.Events, nil
}

func (c *ionConnectClient) convertMedia(media map[string]string) PostMedia {
	var thumbnail *string
	if thumb, ok := media["thumb"]; ok {
		thumbnail = &thumb
	}
	var mediaType string
	switch m, ok := media["m"]; {
	case ok && strings.HasPrefix(m, "image/"):
		mediaType = "image"
	case ok && strings.HasPrefix(m, "video/"):
		mediaType = "video"
	default:
		if strings.HasSuffix(media["url"], "mp4") {
			mediaType = "video"
		} else {
			mediaType = "image"
		}
	}
	return PostMedia{
		Thumbnail: thumbnail,
		URL:       media["url"],
		Type:      mediaType,
	}
}

func (c *ionConnectClient) extractProfileContentMetadata(contentJSON string) (*model.ProfileMetadataContent, error) {
	var content model.ProfileMetadataContent

	if err := json.Unmarshal([]byte(contentJSON), &content); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal profile metadata content")
	}
	return &content, nil
}

func (c *ionConnectClient) getPostFilter(eventAuthor, eventAddress string) model.Filter {
	return model.Filter{
		Kinds: []int{
			model.CustomIONKindEditableTextNote,
			nostr.KindTextNote,
			nostr.KindRepost,
			model.CustomIONKindRepostOfEditableTextNote,
			model.CustomIONKindRepostOfArticle,
			nostr.KindArticle,
			model.KindJobNostrEventCount + 1000,
			nostr.KindBadgeAward,
			nostr.KindProfileMetadata,
		},
		Addresses: []string{eventAddress},
		Limit:     1,
		Search:    "include:dependencies:kind30175>kind6400+kind30175+group+reply include:dependencies:kind30175>kind6400+kind16+group+e include:dependencies:kind30175>kind6400+kind30175+group+q include:dependencies:kind30175>kind6400+kind7+group+content include:dependencies:kind30175>kind6400+kind1754+group+content include:dependencies:kind30175>kind0 include:dependencies:kind30175>kind30008+profile_badges>kind30009>kind8 include:dependencies:kind30175>kind10000 include:dependencies:kind1>kind6400+kind30175+group+reply include:dependencies:kind1>kind6400+kind16+group+e include:dependencies:kind1>kind6400+kind30175+group+q include:dependencies:kind1>kind6400+kind7+group+content include:dependencies:kind1>kind6400+kind1754+group+content include:dependencies:kind1>kind0 include:dependencies:kind1>kind30008+profile_badges>kind30009>kind8 include:dependencies:kind1>kind10000 include:dependencies:kind30023>kind6400+kind30175+group+reply include:dependencies:kind30023>kind6400+kind16+group+e include:dependencies:kind30023>kind6400+kind30175+group+q include:dependencies:kind30023>kind6400+kind7+group+content include:dependencies:kind30023>kind6400+kind1754+group+content include:dependencies:kind30023>kind0 include:dependencies:kind30023>kind30008+profile_badges>kind30009>kind8 include:dependencies:kind30023>kind10000 include:dependencies:kind16>kind6400+kind30175+group+reply include:dependencies:kind16>kind6400+kind16+group+e include:dependencies:kind16>kind6400+kind30175+group+q include:dependencies:kind16>kind6400+kind7+group+content include:dependencies:kind16>kind6400+kind1754+group+content references:false expiration:false !amarker:reply !emarker:reply include:dependencies:kind30175>kind31175 include:dependencies:kind1>kind31175 include:dependencies:kind30023>kind31175",
	}
}

func (p *PostPreview) IsEmpty() bool {
	return p.CreatedAt == nil || p.Content == "" && p.Author.Name == "" && p.Author.DisplayName == "" && p.Author.Avatar == "" &&
		len(p.Media) == 0 && p.Reposts == 0 && p.Comments == 0 && p.Likes == 0
}
