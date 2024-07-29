// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/dfns/dfns-sdk-go/credentials"
	"github.com/dfns/dfns-sdk-go/dfnsapiclient"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

func NewDfnsClient(ctx context.Context, applicationYamlKey string) DfnsClient {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.DFNS.BaseURL == "" {
		log.Panic(errors.Errorf("dfns baseURL not set"))
	}
	if cfg.DFNS.AppID == "" {
		log.Panic(errors.Errorf("dfns appId not set"))
	}
	if cfg.DFNS.ServiceKey == "" {
		log.Panic(errors.Errorf("dfns serviceKey not set"))
	}
	serviceAccountSigner := credentials.NewAsymmetricKeySigner(&credentials.AsymmetricKeySignerConfig{
		PrivateKey: cfg.DFNS.ServiceAccountPrivateKey,
		CredID:     cfg.DFNS.ServiceAccountCredentialID,
	})
	opts, err := dfnsapiclient.NewDfnsAPIOptions(&dfnsapiclient.DfnsAPIConfig{
		AppID:     cfg.DFNS.AppID,
		AuthToken: &cfg.DFNS.ServiceKey,
		BaseURL:   cfg.DFNS.BaseURL,
	}, serviceAccountSigner)
	log.Panic(errors.Wrapf(err, "failed to initialize dfns options"))
	serviceClient := dfnsapiclient.CreateDfnsAPIClient(opts)

	cl := &dfnsClient{serviceAccountClient: serviceClient, userClient: &http.Client{}, cfg: &cfg}
	cl.mustInitProxy()
	//if len(cl.mustListWebhooks(ctx)) == 0 {
	//	_ = cl.mustRegisterAllEventsWebhook(ctx) // TODO: register secret in db to prove events from webhook
	//}
	return cl
}

func (c *dfnsClient) mustInitProxy() {
	remote, err := url.Parse(c.cfg.DFNS.BaseURL)
	log.Panic(errors.Wrapf(err, "failed to parse dfns base url %v", c.cfg.DFNS.BaseURL))
	c.serviceAccountProxy = httputil.NewSingleHostReverseProxy(remote)
	c.userProxy = httputil.NewSingleHostReverseProxy(remote)
	overwriteHostProxyDirector := func(req *http.Request) {
		req.Host = remote.Host
		req.URL.Scheme = remote.Scheme
		req.URL.Host = remote.Host
	}
	c.userProxy.Director = overwriteHostProxyDirector
	c.serviceAccountProxy.Director = overwriteHostProxyDirector
	c.serviceAccountProxy.ErrorHandler = passErrorInResponse
	c.userProxy.ErrorHandler = passErrorInResponse
	c.serviceAccountProxy.Transport = c.serviceAccountClient.Transport
}

func (c *dfnsClient) mustRegisterAllEventsWebhook(ctx context.Context) (whSecret string) {
	jData, err := json.MarshalContext(ctx, struct {
		Url         string   `json:"url"`
		Description string   `json:"description"`
		Status      string   `json:"status"`
		Events      []string `json:"events"`
	}{
		Url:         c.cfg.DFNS.WebhookURL,
		Description: "All events webhook",
		Status:      "Enabled",
		Events:      []string{"*"},
	})
	log.Panic(errors.Wrapf(err, "failed to marshal webhook struct into json"))
	status, resp, _, err := c.ClientCall(ctx, "POST", "/webhooks", http.Header{}, jData)
	log.Panic(errors.Wrapf(err, "failed to register webhook"))
	if status != http.StatusOK {
		log.Panic(errors.Wrapf(err, "failed to register webhook with status %v body %v", status, string(resp)))
	}
	var wh webhook
	if err = json.UnmarshalContext(ctx, resp, &wh); err != nil {
		log.Panic(errors.Wrapf(err, "failed to unmarshal webhook response %v into %#v", string(resp), wh))
	}
	if wh.Secret != nil {
		return *wh.Secret
	}
	return ""
}

func (c *dfnsClient) mustListWebhooks(ctx context.Context) []webhook {
	_, jWebhooks, _, err := c.ClientCall(ctx, "GET", "/webhooks?limit=1", http.Header{}, nil)
	if err != nil {
		log.Panic(errors.Wrapf(err, "failed to list webhooks"))
	}
	var p page[webhook]
	if err = json.UnmarshalContext(ctx, jWebhooks, &p); err != nil {
		log.Panic(errors.Wrapf(err, "failed to unmarshal %v into %#v", string(jWebhooks), p))
	}
	return p.Items
}

func (c *dfnsClient) ProxyCall(ctx context.Context, rw http.ResponseWriter, req *http.Request) {
	if c.urlSupportsServiceAccount(req.URL.Path) {
		c.serviceAccountProxy.ServeHTTP(rw, req)
	} else {
		c.userProxy.ServeHTTP(rw, req)
	}
}
func (c *dfnsClient) ClientCall(ctx context.Context, method, url string, headers http.Header, jsonData []byte) (int, []byte, http.Header, error) {
	if c.urlSupportsServiceAccount(url) {
		return c.doClientCall(ctx, c.serviceAccountClient, method, url, headers, jsonData) // TODO: backoff
	} else {
		return c.doClientCall(ctx, c.userClient, method, url, headers, jsonData)
	}
}
func (c *dfnsClient) urlSupportsServiceAccount(url string) bool {
	return url == "/auth/registration/delegated" ||
		url == "/auth/login/delegated" ||
		url == "/auth/recover/user/delegated"
}

func (c *dfnsClient) doClientCall(ctx context.Context, httpClient *http.Client, method, url string, headers http.Header, jsonData []byte) (int, []byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.DFNS.BaseURL+url, bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, nil, nil, errors.Wrapf(err, "failed to consturct dfns request to %v %v", method, url)
	}

	response, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, errors.Wrapf(err, "failed to exec dfns request to %v %v", method, url)
	}
	defer response.Body.Close()
	respHeaders := response.Header
	bodyData, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, nil, nil, errors.Wrapf(err, "failed to read body data for dfns request to %v %v", method, url)
	}
	if response.StatusCode > http.StatusBadRequest {
		log.Error(errors.Errorf("dfns req to %v %v ended up with %v (data: %v)", method, url, response.StatusCode, string(bodyData)))
	}
	return response.StatusCode, bodyData, respHeaders, nil
}
