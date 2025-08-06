// SPDX-License-Identifier: ice License 1.0

package device_identification

import (
	"context"
	"net/http"
	"time"

	fingerprint "github.com/fingerprintjs/fingerprint-pro-server-api-go-sdk/v7/sdk"
	"github.com/gin-gonic/gin"
	"github.com/imroc/req/v3"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
)

type (
	Client interface {
		ValidateRequestID(ctx context.Context, now *time.Time, requestID, clientIP string) (vistorID string, err error)
		UpdateRequestID(ctx context.Context, requestID, linkedID string, originLinkedID *string) error
	}
	Proxy interface {
		ProxyIdentification(ctx *gin.Context) (status int, body []byte, headers http.Header, err error)
		ProxyBrowserCache(ctx *gin.Context, randonPath string) (status int, body []byte, headers http.Header, err error)
		ProxyAgentDownload(ctx *gin.Context) (status int, body []byte, headers http.Header, err error)
	}
)

var (
	ErrUnknownVisitor = errors.New("unknown visitor")
)

type (
	client struct {
		client           *fingerprint.APIClient
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
			AllowEmpty            bool              `yaml:"allowEmpty"` // TODO: remove once FE will send header
			APIKey                string            `yaml:"apiKey"`
			Region                string            `yaml:"region"`
			AllowedUrls           []string          `yaml:"allowedUrls"`
			AllowedClientAPIKeys  []string          `yaml:"allowedClientApiKeys"`
			AllowedSdks           map[string]string `yaml:"allowedSdks"`
			RequestExpirationTime time.Duration     `yaml:"requestExpirationTime"`
			ProxySecret           string            `yaml:"proxySecret"`
			AgentCDNHost          string            `yaml:"agentCdnHost"`
		} `yaml:"device-identification" mapstructure:"device-identification"`
	}
	agentPayload struct {
		response []byte
		headers  http.Header
	}
)

var (
	validRegions = []fingerprint.Region{fingerprint.RegionUS, fingerprint.RegionEU, fingerprint.RegionAsia}
)

const (
	defaultAgentVersion = "3"
)
