// SPDX-License-Identifier: ice License 1.0

package device_identification

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	fingerprint "github.com/fingerprintjs/fingerprint-pro-server-api-go-sdk/v7/sdk"
	"github.com/pkg/errors"
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
	if !slices.Contains(validRegions, fingerprint.Region(cfg.DeviceIdentification.Region)) {
		log.Panic(errors.Errorf("[DEVICE_IDENTIFICATION] invalid region: %v", cfg.DeviceIdentification.Region))
	}
	internalCfg := fingerprint.NewConfiguration()
	internalCfg.HTTPClient = &http.Client{Transport: &http2.Transport{AllowHTTP: false}}
	internalCfg.ChangeRegion(fingerprint.Region(cfg.DeviceIdentification.Region))
	cl := &client{
		client:           fingerprint.NewAPIClient(internalCfg),
		config:           &cfg,
		validateLinkedId: validateLinkedId,
	}
	return cl
}

func (c *client) ValidateRequestID(ctx context.Context, now *time.Time, requestID, clientIp string) (visitorID string, err error) {
	if requestID == "" || requestID == "-" {
		if c.config.DeviceIdentification.AllowEmpty {
			return "", nil
		}
		return "", ErrUnknownVisitor
	}
	authCtx := context.WithValue(ctx, fingerprint.ContextAPIKey, fingerprint.APIKey{
		Key: c.config.DeviceIdentification.APIKey,
	})
	request, httpResp, err := c.client.FingerprintApi.GetEvent(authCtx, requestID)
	if err != nil {
		var tooManyRequestsError *fingerprint.TooManyRequestsError
		if errors.As(err, &tooManyRequestsError) {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(tooManyRequestsError.RetryAfter()) * time.Second):
				return c.ValidateRequestID(ctx, now, requestID, clientIp)
			}
		} else {
			if httpResp.StatusCode == http.StatusNotFound {
				return "", ErrUnknownVisitor
			}
			bodyBytes, bodyErr := io.ReadAll(httpResp.Body)
			if bodyErr != nil {
				return "", errors.Wrapf(bodyErr, "[device-identification] failed to read visitor ID %q: %v", requestID, err.Error())
			}
			return "", errors.Wrapf(err, "failed to get visits for requestID:%v (%v): %v", requestID, httpResp.StatusCode, string(bodyBytes))
		}
	}

	return c.validateVisitorData(ctx, now, clientIp, request)
}

func (c *client) validateVisitorData(ctx context.Context, now *time.Time, clientIp string, event fingerprint.EventsGetResponse) (string, error) {
	if event.Products == nil || event.Products.Identification == nil || event.Products.Identification.Data == nil {
		return "", errors.Wrap(ErrUnknownVisitor, "no identification data")
	}
	if !slices.Contains(c.config.DeviceIdentification.AllowedUrls, event.Products.Identification.Data.Url) {
		return "", errors.Wrapf(ErrUnknownVisitor, "id / url %v is not allowed", event.Products.Identification.Data.Url)
	}
	if event.Products.Identification.Data.Sdk == nil {
		return "", errors.Wrap(ErrUnknownVisitor, "sdk is not set")
	}
	sdkVer, validPlatform := c.config.DeviceIdentification.AllowedSdks[strings.ToLower(event.Products.Identification.Data.Sdk.Platform)]
	if !validPlatform {
		return "", errors.Wrapf(ErrUnknownVisitor, "invalid sdk platform %v", event.Products.Identification.Data.Sdk.Platform)
	}
	if event.Products.Identification.Data.Sdk.Version != sdkVer {
		return "", errors.Wrapf(ErrUnknownVisitor, "invalid sdk version for %v: %v", event.Products.Identification.Data.Sdk.Platform, event.Products.Identification.Data.Sdk.Version)
	}
	log.Debug(fmt.Sprintf("device identification event for requestID %v: %+v", event.Products.Identification.Data.RequestId, event.Products))
	if now.Before(*event.Products.Identification.Data.Time) || (now.After(*event.Products.Identification.Data.Time) && now.Sub(*event.Products.Identification.Data.Time) > c.config.DeviceIdentification.RequestExpirationTime) {
		return "", errors.Wrapf(ErrUnknownVisitor, "requestID expired %v", event.Products.Identification.Data.Time)
	}
	if event.Products.Identification.Data.Replayed {
		return "", errors.Wrapf(ErrUnknownVisitor, "replayed request")
	}
	if clientIp != "" && event.Products.Identification.Data.Ip != "" {
		ip := net.ParseIP(clientIp)
		skipIPCheck := false
		if ip != nil && ip.IsLoopback() {
			skipIPCheck = true
		}
		if !skipIPCheck {
			if clientIp != event.Products.Identification.Data.Ip {
				return "", errors.Wrapf(ErrUnknownVisitor, "ip mismatch, req>%v, fingerprint>%v", clientIp, event.Products.Identification.Data.Ip)
			}
		}
	}
	if event.Products.IpBlocklist != nil && event.Products.IpBlocklist.Data != nil {
		if event.Products.IpBlocklist.Data.Result {
			return "", errors.Wrapf(ErrUnknownVisitor, "ip blocklist detected")
		}
	}
	if event.Products.Botd != nil && event.Products.Botd.Data != nil && event.Products.Botd.Data.Bot != nil && event.Products.Botd.Data.Bot.Result != nil {
		if *event.Products.Botd.Data.Bot.Result == "bad" {
			return "", errors.Wrapf(ErrUnknownVisitor, "bot detected")
		}
	}
	if event.Products.Tampering != nil && event.Products.Tampering.Data != nil {
		if event.Products.Tampering.Data.Result {
			return "", errors.Wrapf(ErrUnknownVisitor, "tampering detected")
		}
	}
	if event.Products.ClonedApp != nil && event.Products.ClonedApp.Data != nil {
		if event.Products.ClonedApp.Data.Result {
			return "", errors.Wrapf(ErrUnknownVisitor, "cloned app detected")
		}
	}
	if event.Products.Frida != nil && event.Products.Frida.Data != nil {
		if event.Products.Frida.Data.Result {
			return "", errors.Wrapf(ErrUnknownVisitor, "frida detected")
		}
	}
	if event.Products.MitmAttack != nil && event.Products.MitmAttack.Data != nil {
		if event.Products.MitmAttack.Data.Result {
			return "", errors.Wrapf(ErrUnknownVisitor, "mitm detected")
		}
	}
	if event.Products.RootApps != nil && event.Products.RootApps.Data != nil {
		if event.Products.RootApps.Data.Result {
			return "", errors.Wrapf(ErrUnknownVisitor, "root detected")
		}
	}
	if event.Products.Jailbroken != nil && event.Products.Jailbroken.Data != nil {
		if event.Products.Jailbroken.Data.Result {
			return "", errors.Wrapf(ErrUnknownVisitor, "jailbreak detected")
		}
	}
	if event.Products.Emulator != nil && event.Products.Emulator.Data != nil {
		var development bool
		appcfg.MustLoadFromKey("development", &development)
		if (!development) && event.Products.Emulator.Data.Result {
			return "", errors.Wrapf(ErrUnknownVisitor, "emulator detected")
		}
	}
	if event.Products.VirtualMachine != nil && event.Products.VirtualMachine.Data != nil {
		if event.Products.VirtualMachine.Data.Result {
			return "", errors.Wrapf(ErrUnknownVisitor, "vitrual machine detected")
		}
	}
	if event.Products.HighActivity != nil && event.Products.HighActivity.Data != nil {
		if event.Products.HighActivity.Data.Result {
			log.Warn(fmt.Sprintf("high activity detected %v/24h requests, more than 98% of other visitors", event.Products.HighActivity.Data.DailyRequests))
		}
	}
	if event.Products.Velocity != nil && event.Products.Velocity.Data != nil &&
		event.Products.Velocity.Data.DistinctLinkedId != nil && event.Products.Velocity.Data.DistinctLinkedId.Intervals != nil {
		if event.Products.Velocity.Data.DistinctLinkedId.Intervals.Var24h > 2 {
			log.Warn(fmt.Sprintf("detected %v various linkedIds / masterKeys for visitor %v requestId %v",
				event.Products.Velocity.Data.DistinctLinkedId.Intervals.Var24h,
				event.Products.Identification.Data.VisitorId,
				event.Products.Identification.Data.RequestId))
		}
	}
	if event.Products.Identification.Data.Confidence != nil {
		if event.Products.Identification.Data.Confidence.Score <= 0.95 {
			log.Warn(fmt.Sprintf("low confidence score %v (%v) for visitor %v requestId %v",
				event.Products.Identification.Data.Confidence.Score,
				event.Products.Identification.Data.Confidence.Comment,
				event.Products.Identification.Data.VisitorId,
				event.Products.Identification.Data.RequestId))
		}
	}
	if event.Products.Identification.Data.LinkedId != "" {
		return "", errors.Wrapf(c.validateLinkedId(ctx, event.Products.Identification.Data.LinkedId), "failed to validate linked id / master key %v", event.Products.Identification.Data.LinkedId)
	}
	return event.Products.Identification.Data.VisitorId, nil
}

func (c *client) UpdateRequestID(ctx context.Context, requestID, linkedId string, originLinkedId *string) error {
	if c.config.DeviceIdentification.AllowEmpty && requestID == "" {
		return nil
	}

	req := fingerprint.EventsUpdateRequest{
		LinkedId: linkedId,
	}
	if originLinkedId != nil && *originLinkedId != "" {
		req.Tag = &fingerprint.ModelMap{
			"originLinkedId": *originLinkedId,
		}
	}
	authCtx := context.WithValue(ctx, fingerprint.ContextAPIKey, fingerprint.APIKey{
		Key: c.config.DeviceIdentification.APIKey,
	})
	httpResp, err := c.client.FingerprintApi.UpdateEvent(authCtx, req, requestID)
	if err != nil {
		var tooManyRequestsError *fingerprint.TooManyRequestsError
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
