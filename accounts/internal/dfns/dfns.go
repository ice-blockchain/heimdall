// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	stdlibtime "time"

	"github.com/cenkalti/backoff/v4"
	"github.com/dfns/dfns-sdk-go/credentials"
	"github.com/dfns/dfns-sdk-go/dfnsapiclient"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

func NewDfnsClient(ctx context.Context, applicationYamlKey string) (DfnsClient, string) {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.DFNS.BaseURL == "" {
		log.Panic(errors.Errorf("dfns baseURL not set"))
	}
	if cfg.DFNS.AppID == "" {
		cfg.DFNS.AppID = os.Getenv("DFNS_APP_ID")
		if cfg.DFNS.AppID == "" {
			log.Panic(errors.Errorf("dfns appId not set"))
		}
	}
	if cfg.DFNS.ServiceKey == "" {
		cfg.DFNS.ServiceKey = os.Getenv("DFNS_SERVICE_KEY")
		if cfg.DFNS.ServiceKey == "" {
			log.Panic(errors.Errorf("dfns serviceKey not set"))
		}
	}
	if cfg.DFNS.ServiceAccountPrivateKey == "" {
		cfg.DFNS.ServiceAccountPrivateKey = os.Getenv("DFNS_SERVICE_ACCOUNT_PRIVATE_KEY")
		if cfg.DFNS.ServiceAccountPrivateKey == "" {
			pkFile, pkErr := os.Open(os.Getenv("DFNS_SERVICE_ACCOUNT_PRIVATE_KEY_FILE"))
			log.Panic(errors.Wrapf(pkErr, "failed to read dfns private key from file %v"), os.Getenv("DFNS_SERVICE_ACCOUNT_PRIVATE_KEY_FILE"))
			defer pkFile.Close()
			var pk []byte
			pk, pkErr = io.ReadAll(pkFile)
			log.Panic(errors.Wrapf(pkErr, "failed to read dfns private key from file %v"), os.Getenv("DFNS_SERVICE_ACCOUNT_PRIVATE_KEY_FILE"))
			cfg.DFNS.ServiceAccountPrivateKey = string(pk)
			if cfg.DFNS.ServiceAccountPrivateKey == "" {
				log.Panic(errors.Errorf("dfns service account private key not set"))
			}
		}
	}
	if cfg.DFNS.ServiceAccountCredentialID == "" {
		cfg.DFNS.ServiceAccountCredentialID = os.Getenv("DFNS_SERVICE_SERVICE_ACCOUNT_CREDENTIAL_ID")
		if cfg.DFNS.ServiceAccountCredentialID == "" {
			log.Panic(errors.Errorf("dfns service account credential id not set"))
		}
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
	if cfg.DFNS.WebhookURL != "" && len(cl.mustListWebhooks(ctx)) == 0 {
		cl.webhookSecret = cl.mustRegisterAllEventsWebhook(ctx)
	}
	return cl, cl.webhookSecret
}

func (c *dfnsClient) mustInitProxy() {
	remote, err := url.Parse(c.cfg.DFNS.BaseURL)
	log.Panic(errors.Wrapf(err, "failed to parse dfns base url %v", c.cfg.DFNS.BaseURL))
	c.serviceAccountProxy = httputil.NewSingleHostReverseProxy(remote)
	c.userProxy = httputil.NewSingleHostReverseProxy(remote)
	overwriteHostProxyDirector := func(req *http.Request) {
		req.RequestURI = ""
		req.Host = remote.Host
		req.URL.Scheme = remote.Scheme
		req.URL.Host = remote.Host
		req.Header.Set(appIDHeader, c.cfg.DFNS.AppID)
	}
	c.userProxy.Director = overwriteHostProxyDirector
	c.serviceAccountProxy.Director = overwriteHostProxyDirector
	c.serviceAccountProxy.ErrorHandler = passErrorInResponse
	c.userProxy.ErrorHandler = passErrorInResponse
	c.serviceAccountProxy.Transport = c.serviceAccountClient.Transport
}
func (c *dfnsClient) VerifyWebhookSecret(fromWebhook string) bool {
	return c.webhookSecret != "" && c.webhookSecret == fromWebhook
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
	status, resp, err := c.clientCall(ctx, "POST", "/webhooks", http.Header{}, jData)
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
	_, jWebhooks, err := c.clientCall(ctx, "GET", "/webhooks?limit=1", http.Header{}, nil)
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
func (c *dfnsClient) clientCall(ctx context.Context, method, url string, headers http.Header, jsonData []byte) (int, []byte, error) {
	if c.urlSupportsServiceAccount(url) {
		return retry(ctx, func() (status int, body []byte, err error) {
			return c.doClientCall(ctx, c.serviceAccountClient, method, url, headers, jsonData)
		})
	} else {
		return retry(ctx, func() (status int, body []byte, err error) {
			return c.doClientCall(ctx, c.userClient, method, url, headers, jsonData)
		})
	}
}
func (c *dfnsClient) urlSupportsServiceAccount(url string) bool {
	return url == "/auth/registration/delegated" ||
		url == "/auth/login/delegated" ||
		url == "/auth/recover/user/delegated"
}

func (c *dfnsClient) doClientCall(ctx context.Context, httpClient *http.Client, method, url string, headers http.Header, jsonData []byte) (int, []byte, error) {
	headers.Set("Content-Type", "application/json")
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.DFNS.BaseURL+url, bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, nil, errors.Wrapf(err, "failed to consturct dfns request to %v %v", method, url)
	}
	req.Header = headers

	response, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, errors.Wrapf(err, "failed to exec dfns request to %v %v", method, url)
	}
	defer response.Body.Close()
	bodyData, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, nil, errors.Wrapf(err, "failed to read body data for dfns request to %v %v", method, url)
	}
	if response.StatusCode >= http.StatusBadRequest && err == nil {
		err = errors.Errorf("dfns req to %v %v ended up with %v (data: %v)", method, url, response.StatusCode, string(bodyData))
	}
	return response.StatusCode, bodyData, nil
}
func (c *dfnsClient) StartDelegatedRecovery(ctx context.Context, username string, credentialId string) (*StartedDelegatedRecovery, error) {
	params := struct {
		Username     string `json:"username"`
		CredentialID string `json:"credentialId"`
	}{
		Username:     username,
		CredentialID: credentialId,
	}
	header := http.Header{}
	header.Set(appIDHeader, appID(ctx))
	resp, err := dfnsCall[struct {
		Username     string `json:"username"`
		CredentialID string `json:"credentialId"`
	}, StartedDelegatedRecovery](ctx, c, params, "POST", "/auth/recover/user/delegated", header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to start delegated recovery for username %v credID %v", username, credentialId)
	}
	return resp, nil
}
func (c *dfnsClient) StartDelegatedRegistration(ctx context.Context, username, kind string) (*StartedDelegatedRegistration, error) {
	params := struct {
		Email string `json:"email"`
		Kind  string `json:"kind"`
	}{
		Email: username,
		Kind:  kind,
	}
	header := http.Header{}
	header.Set(appIDHeader, c.cfg.DFNS.AppID)
	resp, err := dfnsCall[struct {
		Email string `json:"email"`
		Kind  string `json:"kind"`
	}, StartedDelegatedRegistration](ctx, c, params, "POST", "/auth/registration/delegated", header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to start delegated registration for username/email %v kind %v", username, kind)
	}
	return resp, nil
}

func dfnsCall[REQ any, RESP any](ctx context.Context, c *dfnsClient, params REQ, method, uri string, headers http.Header) (*RESP, error) {
	postData, err := json.MarshalContext(ctx, params)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to serialize %#v to json")
	}
	status, body, err := c.clientCall(ctx, "POST", uri, headers, postData)
	if err != nil {
		if dfnsErr := ParseErrAsDfnsInternalErr(err); dfnsErr != nil {
			return nil, errors.Wrapf(dfnsErr, "failed to call %v %v", method, uri)
		}
		return nil, errors.Wrapf(err, "failed to call %v %v", method, uri)
	} else if status >= http.StatusBadRequest {
		err = buildDfnsError(status, uri, body)
		return nil, errors.Wrapf(err, "failed to call %v %v", method, uri)
	}
	var resp RESP
	if err = json.UnmarshalContext(ctx, body, &resp); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal response %v for call %v %v", string(body))
	}
	return &resp, nil
}

func dfnsAuthHeader(ctx context.Context) string {
	return ctx.Value(AuthHeaderCtxValue).(string)
}
func appID(ctx context.Context) string {
	return ctx.Value(AuthHeaderCtxValue).(string)
}

func (c *dfnsClient) GetUser(ctx context.Context, userID string) (*User, error) {
	headers := http.Header{}
	headers.Set(appIDHeader, c.cfg.DFNS.AppID)
	headers.Set("Authorization", dfnsAuthHeader(ctx))
	uri := fmt.Sprintf("/auth/users/%v", userID)
	status, body, err := c.clientCall(ctx, "GET", uri, headers, nil)
	if status >= http.StatusBadRequest && err == nil {
		err = buildDfnsError(status, uri, body)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user %v from dfns", userID)
	}
	var usr User
	if err = json.UnmarshalContext(ctx, body, &usr); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal response %v for to User", string(body))
	}
	return &usr, nil
}

func retry(ctx context.Context, op func() (status int, body []byte, err error)) (status int, body []byte, err error) {
	err = backoff.RetryNotify(
		func() error {
			status, body, err = op()
			return err
		},
		backoff.WithContext(&backoff.ExponentialBackOff{
			InitialInterval:     10 * stdlibtime.Millisecond, //nolint:mnd,gomnd // .
			RandomizationFactor: 0.5,                         //nolint:mnd,gomnd // .
			Multiplier:          2.5,                         //nolint:mnd,gomnd // .
			MaxInterval:         5 * stdlibtime.Second,
			MaxElapsedTime:      requestDeadline,
			Stop:                backoff.Stop,
			Clock:               backoff.SystemClock,
		}, ctx),
		func(e error, next stdlibtime.Duration) {
			log.Error(errors.Wrapf(e, "call to dfns failed. retrying in %v... ", next))
		})
	return status, body, err
}
