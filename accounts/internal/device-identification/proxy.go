// SPDX-License-Identifier: ice License 1.0

package device_identification

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	stdlibtime "time"

	fingerprint "github.com/fingerprintjs/fingerprint-pro-server-api-go-sdk/v7/sdk"
	"github.com/gin-gonic/gin"
	"github.com/imroc/req/v3"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"golang.org/x/net/http2"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

func init() {
	req.DefaultClient().GetClient().Transport = &http2.Transport{AllowHTTP: false}
	req.DefaultClient().GetClient().Timeout = 30 * stdlibtime.Second
}

func NewProxy(applicationYamlKey string, serviceVersion string) Proxy {
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
	if cfg.DeviceIdentification.ProxySecret == "" {
		cfg.DeviceIdentification.ProxySecret = os.Getenv("DEVICE_IDENTIFICATION_PROXY_KEY")
		if cfg.DeviceIdentification.ProxySecret == "" {
			log.Panic(errors.Errorf("[DEVICE_IDENTIFICATION] empty proxy key"))
		}
	}
	if len(cfg.DeviceIdentification.AllowedClientAPIKeys) == 0 {
		cfg.DeviceIdentification.AllowedClientAPIKeys = strings.Split(os.Getenv("DEVICE_IDENTIFICATION_ALLOWED_CLIENT_KEYS"), ",")
	}
	internalCfg := fingerprint.NewConfiguration()
	internalCfg.ChangeRegion(fingerprint.Region(cfg.DeviceIdentification.Region))

	return &proxy{
		config:             &cfg,
		serviceVersion:     serviceVersion,
		client:             req.C().SetBaseURL(internalCfg.GetBasePath()),
		agentPayloadsCache: ttlcache.New[string, *agentPayload](ttlcache.WithTTL[string, *agentPayload](15 * stdlibtime.Minute)),
	}
}

func (p *proxy) ProxyIdentification(ginCtx *gin.Context) (status int, body []byte, headers http.Header, err error) {
	return p.proxyReqToDeviceIdentificationService(ginCtx, func(request *req.Request) (*req.Response, error) {
		return request.
			SetHeader("FPJS-Proxy-Secret", p.config.DeviceIdentification.ProxySecret).
			SetHeader("FPJS-Proxy-Client-IP", ginCtx.ClientIP()).
			SetHeader("FPJS-Proxy-Forwarded-Host", ginCtx.Request.Host).
			Post("/")
	})
}

func (p *proxy) ProxyBrowserCache(ginCtx *gin.Context, randomPath string) (status int, body []byte, headers http.Header, err error) {
	return p.proxyReqToDeviceIdentificationService(ginCtx, func(request *req.Request) (*req.Response, error) {
		return request.Get(randomPath)
	})
}
func (p *proxy) ProxyAgentDownload(ginCtx *gin.Context) (status int, body []byte, headers http.Header, err error) {
	if ginCtx.Err() != nil {
		return http.StatusBadGateway, nil, nil, errors.Wrapf(ginCtx.Err(), "failed to fetch agent")
	}
	type agentDownloadParams struct {
		Version       string `form:"version"`
		ClientApiKey  string `form:"apiKey"`
		LoaderVersion string `form:"loaderVersion"`
	}
	var params agentDownloadParams
	if err := ginCtx.BindQuery(&params); err != nil {
		return http.StatusUnprocessableEntity, nil, nil, errors.Wrapf(err, "failed to parse query agentDownloadParams")
	}
	if params.Version == "" {
		params.Version = defaultAgentVersion
	}
	if !slices.Contains(p.config.DeviceIdentification.AllowedClientAPIKeys, params.ClientApiKey) {
		return http.StatusForbidden, nil, nil, errors.Errorf("invalid client api key %v", params.ClientApiKey)
	}
	url := fmt.Sprintf("/v%v/%v%v", params.Version, params.ClientApiKey, params.LoaderVersion)
	item, found := p.agentPayloadsCache.GetOrSetFunc(url, func() *agentPayload {
		status, body, headers, err = p.proxyReqToDeviceIdentificationService(ginCtx, func(request *req.Request) (*req.Response, error) {
			return req.SetBaseURL(p.config.DeviceIdentification.AgentCDNHost).R().Get(url)
		})
		if status == http.StatusOK && err == nil && len(body) > 0 {
			return &agentPayload{
				response: body,
				headers:  headers,
			}
		} else {
			return nil
		}
	})
	if item.Value() == nil {
		if !found {
			return status, body, headers, err
		}
		p.agentPayloadsCache.Delete(url)
		return p.ProxyAgentDownload(ginCtx)
	}

	return status, item.Value().response, item.Value().headers, err
}

func (p *proxy) proxyReqToDeviceIdentificationService(ginCtx *gin.Context, execRequest func(request *req.Request) (*req.Response, error)) (status int, body []byte, headers http.Header, err error) {
	var bodyBytes []byte
	if ginCtx.Request.Body != nil {
		bodyBytes, err = io.ReadAll(ginCtx.Request.Body)
		if err != nil {
			ginCtx.Status(http.StatusBadRequest)
			return
		}
		ginCtx.Request.Body.Close()
	}
	request := p.client.R().
		SetContext(ginCtx).
		SetRetryCount(3).
		SetRetryInterval(func(resp *req.Response, attempt int) stdlibtime.Duration {
			return 1 * stdlibtime.Second
		}).
		SetRetryHook(func(resp *req.Response, err error) {
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to call device identification %v, retrying...", p.client.BaseURL))
			} else {
				log.Error(errors.Errorf("failed to call device identification %v with status code:%v, retrying...", p.client.BaseURL, resp.GetStatusCode()))
			}
		}).
		SetRetryCondition(func(resp *req.Response, err error) bool {
			return err != nil ||
				(resp.GetStatusCode() != http.StatusOK && resp.GetStatusCode() != http.StatusTooManyRequests &&
					resp.GetStatusCode() != http.StatusForbidden && resp.GetStatusCode() != http.StatusNotFound)
		}).
		SetHeaders(trimHeaders(ginCtx.Request.Header)).
		SetQueryString(ginCtx.Request.URL.RawQuery).
		SetCookies(trimCookies(ginCtx)...).
		AddQueryParam("ii", fmt.Sprintf("custom-proxy-integration/%v/heimdall", p.serviceVersion)).
		SetBodyBytes(bodyBytes)
	if resp, err := execRequest(request); err != nil {
		return 0, nil, nil, errors.Wrapf(err, "failed to call device identification %v", p.client.BaseURL)
	} else if statusCode := resp.GetStatusCode(); statusCode != http.StatusOK {
		b, err2 := resp.ToBytes()
		return resp.GetStatusCode(), b, resp.Header, err2
	} else if data, err2 := resp.ToBytes(); err2 != nil {
		return 0, nil, nil, errors.Wrapf(err2, "failed to device identification %v response", p.client.BaseURL)
	} else {
		return resp.StatusCode, data, resp.Header, nil
	}
}

func trimHeaders(header http.Header) map[string]string {
	res := make(map[string]string)
	for k, v := range header {
		if k == "Cookie" {
			continue
		}
		res[k] = v[0]
	}
	return res
}

func trimCookies(ginCtx *gin.Context) []*http.Cookie {
	cookie, err := ginCtx.Request.Cookie("_iidt")
	if err != nil {
		return []*http.Cookie{}
	}
	return []*http.Cookie{cookie}
}
