// SPDX-License-Identifier: ice License 1.0

package deviceidentification

import (
	"context"
	"net/http"
	"time"

	deviceidentificationsdk "github.com/fingerprintjs/fingerprint-pro-server-api-go-sdk/v7/sdk"
	"github.com/gin-gonic/gin"
	"github.com/imroc/req/v3"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
)

const deviceIdentificationDisabled = true

type (
	Client interface {
		ValidateRequestID(ctx context.Context, now *time.Time, requestID, clientIP string) (vistorID, devicePubKey string, err error)
		UpdateRequestID(ctx context.Context, requestID, linkedID string, originLinkedID *string) error
		HealthCheck(ctx context.Context) error
	}
	Proxy interface {
		ProxyIdentification(ctx *gin.Context) (status int, body []byte, headers http.Header, err error)
		ProxyBrowserCache(ctx *gin.Context, randomPath string) (status int, body []byte, headers http.Header, err error)
		ProxyAgentDownload(ctx *gin.Context) (status int, body []byte, headers http.Header, err error)
		HealthCheck(ctx context.Context) error
	}
)

var (
	ErrUnknownDevice = errors.New("unknown device")
)

type (
	client struct {
		client           *deviceidentificationsdk.APIClient
		config           *config
		validateLinkedId func(ctx context.Context, linkedId string) error
	}
	proxy struct {
		config             *config
		client             *req.Client
		serviceVersion     string
		agentPayloadsCache *ttlcache.Cache[string, *agentPayload]
	}
	config struct {
		DeviceIdentification struct {
			APIKey                string            `yaml:"apiKey" mapstructure:"apiKey"`
			Region                string            `yaml:"region" mapstructure:"region"`
			AllowedUrls           []string          `yaml:"allowedUrls" mapstructure:"allowedUrls"`
			AllowedClientAPIKeys  []string          `yaml:"allowedClientApiKeys" mapstructure:"allowedClientApiKeys"`
			AllowedSdks           map[string]string `yaml:"allowedSdks" mapstructure:"allowedSdks"`
			RequestExpirationTime time.Duration     `yaml:"requestExpirationTime" mapstructure:"requestExpirationTime"`
			SuspectThreshold      int               `yaml:"suspectThreshold" mapstructure:"suspectThreshold"`
			ProxySecret           string            `yaml:"proxySecret" mapstructure:"proxySecret"`
			AgentCDNHost          string            `yaml:"agentCdnHost" mapstructure:"agentCdnHost"`
		} `yaml:"device-identification" mapstructure:"device-identification"`
	}
	agentPayload struct {
		response []byte
		headers  http.Header
	}
)

var (
	validRegions = []deviceidentificationsdk.Region{deviceidentificationsdk.RegionUS, deviceidentificationsdk.RegionEU, deviceidentificationsdk.RegionAsia}
)

const (
	defaultAgentVersion = "3"
)
