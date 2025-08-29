// SPDX-License-Identifier: ice License 1.0

package deviceidentification

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	deviceidentificationsdk "github.com/fingerprintjs/fingerprint-pro-server-api-go-sdk/v7/sdk"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"golang.org/x/mod/semver"
	"golang.org/x/net/http2"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

func New(applicationYamlKey string, validateLinkedId func(context.Context, string) error) Client {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.DeviceIdentification.APIKey == "" {
		cfg.DeviceIdentification.APIKey = os.Getenv("DEVICE_IDENTIFICATION_API_KEY")
		if cfg.DeviceIdentification.APIKey == "" {
			log.Panic(errors.Errorf("[DEVICE_IDENTIFICATION] empty api key"))
		}
	}
	if !slices.Contains(validRegions, deviceidentificationsdk.Region(cfg.DeviceIdentification.Region)) {
		log.Panic(errors.Errorf("[DEVICE_IDENTIFICATION] invalid region: %v", cfg.DeviceIdentification.Region))
	}
	internalCfg := deviceidentificationsdk.NewConfiguration()
	internalCfg.HTTPClient = &http.Client{Transport: &http2.Transport{AllowHTTP: false}}
	internalCfg.ChangeRegion(deviceidentificationsdk.Region(cfg.DeviceIdentification.Region))
	cl := &client{
		client:           deviceidentificationsdk.NewAPIClient(internalCfg),
		config:           &cfg,
		validateLinkedId: validateLinkedId,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := cl.HealthCheck(ctx); err != nil {
		log.Panic(errors.Wrapf(err, "initial health check of device identification failed"))
	}
	return cl
}

func (c *client) ValidateRequestID(ctx context.Context, now *time.Time, requestID, clientIp string) (visitorID, devicePubKey string, err error) {
	if requestID == "" || requestID == "-" {
		if deviceIdentificationDisabled { // TODO: remove once FE implemented.
			return "", "", nil
		}
		return "", "", ErrUnknownDevice
	}
	request, err := c.getEvent(ctx, requestID)
	if err != nil {
		return "", "", errors.Wrapf(err, "failed to get event by requestID %v", requestID)
	}
	return c.validateVisitorData(ctx, now, clientIp, request)
}

func (c *client) validateVisitorData(ctx context.Context, now *time.Time, clientIp string, event *deviceidentificationsdk.EventsGetResponse) (visitorID string, devicePubkey string, err error) {
	if event.Products == nil || event.Products.Identification == nil || event.Products.Identification.Data == nil {
		return "", "", errors.Wrap(ErrUnknownDevice, "no identification data")
	}
	jProducts, err := json.Marshal(event.Products)
	if err != nil {
		jProducts = []byte(fmt.Sprintf("%+v", event.Products))
	}
	log.Debug(fmt.Sprintf("device identification event for requestID %v: %+v", event.Products.Identification.Data.RequestId, string(jProducts)))
	if !slices.Contains(c.config.DeviceIdentification.AllowedUrls, event.Products.Identification.Data.Url) {
		return "", "", errors.Wrapf(ErrUnknownDevice, "request %v id / url %v is not allowed", event.Products.Identification.Data.RequestId, event.Products.Identification.Data.Url)
	}
	if event.Products.Identification.Data.Sdk == nil {
		return "", "", errors.Wrapf(ErrUnknownDevice, "request %v sdk is not set", event.Products.Identification.Data.RequestId)
	}
	sdkVer, validPlatform := c.config.DeviceIdentification.AllowedSdks[strings.ToLower(event.Products.Identification.Data.Sdk.Platform)]
	if !validPlatform {
		return "", "", errors.Wrapf(ErrUnknownDevice, "request %v invalid sdk platform %v", event.Products.Identification.Data.RequestId, event.Products.Identification.Data.Sdk.Platform)
	}

	if semver.Compare(event.Products.Identification.Data.Sdk.Version, sdkVer) < 0 {
		return "", "", errors.Wrapf(ErrUnknownDevice, "request %v invalid sdk version for %v: %v", event.Products.Identification.Data.RequestId, event.Products.Identification.Data.Sdk.Platform, event.Products.Identification.Data.Sdk.Version)
	}
	if now.Before(*event.Products.Identification.Data.Time) || (now.After(*event.Products.Identification.Data.Time) && now.Sub(*event.Products.Identification.Data.Time) > c.config.DeviceIdentification.RequestExpirationTime) {
		return "", "", errors.Wrapf(ErrUnknownDevice, "requestID %v expired %v", event.Products.Identification.Data.RequestId, event.Products.Identification.Data.Time)
	}
	if devicePubkey, err = c.verifySignatureByDeviceKey(event, now); err != nil {
		return "", "", errors.Wrapf(ErrUnknownDevice, "invalid device signature: %v request %v", err, event.Products.Identification.Data.RequestId)
	}
	if event.Products.Identification.Data.Replayed {
		return "", "", errors.Wrapf(ErrUnknownDevice, "replayed request %v", event.Products.Identification.Data.RequestId)
	}
	if clientIp != "" && event.Products.Identification.Data.Ip != "" {
		ip := net.ParseIP(clientIp)
		skipIPCheck := false
		if ip != nil && ip.IsLoopback() {
			skipIPCheck = true
		}
		if !skipIPCheck {
			if clientIp != event.Products.Identification.Data.Ip {
				return "", "", errors.Wrapf(ErrUnknownDevice, "request %v ip mismatch, req>%v, deviceidentificationsdk>%v", event.Products.Identification.Data.RequestId, clientIp, event.Products.Identification.Data.Ip)
			}
		}
	}
	if event.Products.IpBlocklist != nil && event.Products.IpBlocklist.Data != nil {
		if event.Products.IpBlocklist.Data.Result {
			return "", "", errors.Wrapf(ErrUnknownDevice, "request %v ip blocklist detected", event.Products.Identification.Data.RequestId)
		}
	}
	if event.Products.Botd != nil && event.Products.Botd.Data != nil && event.Products.Botd.Data.Bot != nil && event.Products.Botd.Data.Bot.Result != nil {
		if *event.Products.Botd.Data.Bot.Result == "bad" {
			return "", "", errors.Wrapf(ErrUnknownDevice, "request %v bot detected", event.Products.Identification.Data.RequestId)
		}
	}
	if event.Products.Tampering != nil && event.Products.Tampering.Data != nil {
		if event.Products.Tampering.Data.Result {
			return "", "", errors.Wrapf(ErrUnknownDevice, "request %v tampering detected", event.Products.Identification.Data.RequestId)
		}
	}
	if event.Products.ClonedApp != nil && event.Products.ClonedApp.Data != nil {
		if event.Products.ClonedApp.Data.Result {
			return "", "", errors.Wrapf(ErrUnknownDevice, "request %v cloned app detected", event.Products.Identification.Data.RequestId)
		}
	}
	if event.Products.Frida != nil && event.Products.Frida.Data != nil {
		if event.Products.Frida.Data.Result {
			return "", "", errors.Wrapf(ErrUnknownDevice, "request %v frida detected", event.Products.Identification.Data.RequestId)
		}
	}
	if event.Products.MitmAttack != nil && event.Products.MitmAttack.Data != nil {
		if event.Products.MitmAttack.Data.Result {
			return "", "", errors.Wrapf(ErrUnknownDevice, "request %v mitm detected", event.Products.Identification.Data.RequestId)
		}
	}
	if event.Products.RootApps != nil && event.Products.RootApps.Data != nil {
		if event.Products.RootApps.Data.Result {
			return "", "", errors.Wrapf(ErrUnknownDevice, "request %v root detected", event.Products.Identification.Data.RequestId)
		}
	}
	if event.Products.Jailbroken != nil && event.Products.Jailbroken.Data != nil {
		if event.Products.Jailbroken.Data.Result {
			return "", "", errors.Wrapf(ErrUnknownDevice, "request %v jailbreak detected", event.Products.Identification.Data.RequestId)
		}
	}
	if event.Products.Emulator != nil && event.Products.Emulator.Data != nil {
		var development bool
		appcfg.MustLoadFromKey("development", &development)
		if (!development) && event.Products.Emulator.Data.Result {
			return "", "", errors.Wrapf(ErrUnknownDevice, "request %v emulator detected", event.Products.Identification.Data.RequestId)
		}
	}
	if c.config.DeviceIdentification.SuspectThreshold > 0 {
		if event.Products.SuspectScore != nil && event.Products.SuspectScore.Data != nil {
			if int(event.Products.SuspectScore.Data.Result) > c.config.DeviceIdentification.SuspectThreshold {
				return "", "", errors.Wrapf(ErrUnknownDevice, "suspect score is high: %v for request %v", event.Products.SuspectScore.Data.Result, event.Products.Identification.Data.RequestId)
			}
		}
	}
	if event.Products.VirtualMachine != nil && event.Products.VirtualMachine.Data != nil {
		if event.Products.VirtualMachine.Data.Result {
			return "", "", errors.Wrapf(ErrUnknownDevice, "request %v vitrual machine detected", event.Products.Identification.Data.RequestId)
		}
	}
	if event.Products.HighActivity != nil && event.Products.HighActivity.Data != nil {
		if event.Products.HighActivity.Data.Result {
			log.Warn(fmt.Sprintf("request %v: high activity detected %v/24h requests, more than 98% of other visitors", event.Products.Identification.Data.RequestId, event.Products.HighActivity.Data.DailyRequests))
		}
	}
	if event.Products.Velocity != nil && event.Products.Velocity.Data != nil &&
		event.Products.Velocity.Data.DistinctLinkedId != nil && event.Products.Velocity.Data.DistinctLinkedId.Intervals != nil {
		if event.Products.Velocity.Data.DistinctLinkedId.Intervals.Var24h > 2 {
			log.Warn(fmt.Sprintf("request %v detected %v various linkedIds / masterKeys for visitor %v requestId %v",
				event.Products.Identification.Data.RequestId,
				event.Products.Velocity.Data.DistinctLinkedId.Intervals.Var24h,
				event.Products.Identification.Data.VisitorId,
				event.Products.Identification.Data.RequestId))
		}
	}
	if event.Products.Identification.Data.Confidence != nil {
		if event.Products.Identification.Data.Confidence.Score <= 0.95 {
			log.Warn(fmt.Sprintf("request %v: low confidence score %v (%v) for visitor %v requestId %v",
				event.Products.Identification.Data.RequestId,
				event.Products.Identification.Data.Confidence.Score,
				event.Products.Identification.Data.Confidence.Comment,
				event.Products.Identification.Data.VisitorId,
				event.Products.Identification.Data.RequestId))
		}
	}
	if event.Products.Identification.Data.LinkedId != "" {
		if err = c.validateLinkedId(ctx, event.Products.Identification.Data.LinkedId); err != nil {
			return "", "", errors.Wrapf(err, "failed to validate linked id / master key %v", event.Products.Identification.Data.LinkedId)
		}
	}
	if event.Products.Identification.Data.Tag != nil {
		if originID, hasOrigin := (*event.Products.Identification.Data.Tag)["originLinkedId"]; hasOrigin && originID != "" {
			if err = c.validateLinkedId(ctx, originID.(string)); err != nil {
				return "", "", errors.Wrapf(err, "failed to validate linked id / master key %v", originID)
			}
		}
	}
	return event.Products.Identification.Data.VisitorId, devicePubkey, nil
}

func (c *client) deviceIdentificationSignedData(event *deviceidentificationsdk.EventsGetResponse, createdAt string) []byte {
	return []byte(strings.Join([]string{
		strings.ToLower(event.Products.Identification.Data.BrowserDetails.Os),
		strings.ToLower(event.Products.Identification.Data.BrowserDetails.OsVersion),
		strings.ToLower(event.Products.Vpn.Data.OriginTimezone),
		createdAt,
	}, ":"))
}

func (c *client) verifySignatureByDeviceKey(event *deviceidentificationsdk.EventsGetResponse, now *time.Time) (string, error) {
	if event.Products.Identification.Data.Tag == nil ||
		(*event.Products.Identification.Data.Tag)["signature"] == nil {
		return "", errors.New("no signature")
	}
	split := strings.Split((*event.Products.Identification.Data.Tag)["signature"].(string), ":")
	if len(split) != 3 {
		return "", errors.New("malformed signature")
	}
	createdAtUnix, err := strconv.ParseInt(split[0], 10, 64)
	if err != nil {
		return "", errors.Wrapf(err, "malformed createdAt part: %v", split[0])
	}
	var createdAt time.Time
	switch {
	case createdAtUnix < 1e10: // Seconds.
		createdAt = time.Unix(int64(createdAtUnix), 0)
	case createdAtUnix < 1e13: // Milliseconds.
		createdAt = time.UnixMilli(int64(createdAtUnix))
	case createdAtUnix < 1e16: // Microseconds.
		createdAt = time.UnixMicro(int64(createdAtUnix))
	default: // Nanoseconds.
		createdAt = time.Unix(int64(createdAtUnix)/1e9, int64(createdAtUnix)%1e9)
	}
	if createdAt.After(*now) || now.Sub(createdAt) > c.config.DeviceIdentification.RequestExpirationTime {
		return "", errors.Errorf("expired createdAt in device signature %v", createdAtUnix)
	}
	key, err := hex.DecodeString(split[1])
	if err != nil {
		return "", errors.Wrapf(err, "malformed key part: ", split[1])
	}
	signature, err := hex.DecodeString(split[2])
	if err != nil {
		return "", errors.Wrapf(err, "malformed signature part: %v", split[2])
	}
	if !ed25519.Verify(key, c.deviceIdentificationSignedData(event, split[0]), signature) {
		return "", errors.New("invalid signature")
	}
	return split[1], nil
}

func (c *client) getEvent(ctx context.Context, requestID string) (*deviceidentificationsdk.EventsGetResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	authCtx := context.WithValue(ctx, deviceidentificationsdk.ContextAPIKey, deviceidentificationsdk.APIKey{
		Key: c.config.DeviceIdentification.APIKey,
	})
	request, httpResp, err := c.client.FingerprintApi.GetEvent(authCtx, requestID)
	if err != nil {
		var tooManyRequestsError *deviceidentificationsdk.TooManyRequestsError
		if errors.As(err, &tooManyRequestsError) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(tooManyRequestsError.RetryAfter()) * time.Second):
				return c.getEvent(ctx, requestID)
			}
		} else {
			if httpResp.StatusCode == http.StatusNotFound {
				return nil, ErrUnknownDevice
			}
			bodyBytes, bodyErr := io.ReadAll(httpResp.Body)
			if bodyErr != nil {
				return nil, errors.Wrapf(bodyErr, "[device-identification] failed to read visitor ID %q: %v", requestID, err.Error())
			}
			return nil, errors.Wrapf(err, "failed to get visits for requestID:%v (%v): %v", requestID, httpResp.StatusCode, string(bodyBytes))
		}
	}
	return &request, nil
}

func (c *client) UpdateRequestID(ctx context.Context, requestID, linkedId string, originLinkedId *string) error {
	if deviceIdentificationDisabled && requestID == "" { // TODO: remove once FE implemented.
		return nil
	}

	req := deviceidentificationsdk.EventsUpdateRequest{
		LinkedId: linkedId,
	}
	if originLinkedId != nil && *originLinkedId != "" {
		req.Tag = &deviceidentificationsdk.ModelMap{
			"originLinkedId": *originLinkedId,
		}
	}
	authCtx := context.WithValue(ctx, deviceidentificationsdk.ContextAPIKey, deviceidentificationsdk.APIKey{
		Key: c.config.DeviceIdentification.APIKey,
	})
	httpResp, err := c.client.FingerprintApi.UpdateEvent(authCtx, req, requestID)
	if err != nil {
		var tooManyRequestsError *deviceidentificationsdk.TooManyRequestsError
		if errors.As(err, &tooManyRequestsError) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(tooManyRequestsError.RetryAfter()) * time.Second):
				return c.UpdateRequestID(ctx, requestID, linkedId, originLinkedId)
			}
		} else {
			if httpResp != nil {
				bodyBytes, bodyErr := io.ReadAll(httpResp.Body)
				if bodyErr != nil {
					return errors.Wrapf(bodyErr, "[device-identification] failed to update request %q: %v", requestID, err.Error())
				}
				return errors.Wrapf(err, "failed to update requestID:%v (%v): %v", requestID, httpResp.StatusCode, string(bodyBytes))
			}
			return errors.Wrapf(err, "failed to update requestID:%v (%v): %v", requestID)
		}
	}
	return nil
}

func (c *client) HealthCheck(ctx context.Context) error {
	_, err := c.getEvent(ctx, "bogus")
	if errors.Is(err, ErrUnknownDevice) {
		err = nil
	}
	return errors.Wrapf(err, "device identification sdk health check failed")
}
