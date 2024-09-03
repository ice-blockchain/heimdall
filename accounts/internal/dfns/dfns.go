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
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func NewDfnsClient(ctx context.Context, db *storage.DB, applicationYamlKey string) DfnsClient {
	var cfg config
	cfg.loadCfg(applicationYamlKey)
	serviceAccountSigner := credentials.NewAsymmetricKeySigner(&credentials.AsymmetricKeySignerConfig{
		PrivateKey: cfg.DFNS.ServiceAccountPrivateKey,
		CredID:     cfg.DFNS.ServiceAccountCredentialID,
	})
	opts, err := dfnsapiclient.NewDfnsAPIOptions(&dfnsapiclient.DfnsAPIConfig{
		AppID:     cfg.DFNS.AppID,
		AuthToken: &cfg.DFNS.ServiceKey,
		BaseURL:   cfg.DFNS.BaseURL,
	}, serviceAccountSigner)
	log.Panic(errors.Wrapf(err, "failed to initialize dfns options with serviceAccount signer"))
	serviceClient := dfnsapiclient.CreateDfnsAPIClient(opts)
	userOpts, err := dfnsapiclient.NewDfnsAPIOptions(&dfnsapiclient.DfnsAPIConfig{
		AppID:     cfg.DFNS.AppID,
		AuthToken: &cfg.DFNS.ServiceKey,
		BaseURL:   cfg.DFNS.BaseURL,
	}, nil)
	log.Panic(errors.Wrapf(err, "failed to initialize dfns options for user"))
	cl := &dfnsClient{serviceAccountClient: serviceClient, userClient: dfnsapiclient.CreateDfnsAPIClient(userOpts), cfg: &cfg}
	cl.mustInitProxy()
	cl.mustSetupWebhookOrLoadSecret(ctx, db, &cfg)

	return cl
}

func (c *dfnsClient) mustSetupWebhookOrLoadSecret(ctx context.Context, db *storage.DB, cfg *config) {
	var err error
	whCtx, whCancel := context.WithTimeout(ctx, 30*stdlibtime.Second)
	defer whCancel()
	whLock := storage.NewMutex(db, "registerWebhook")
	for whCtx.Err() == nil {
		if err = whLock.Lock(whCtx); err != nil {
			if !errors.Is(err, storage.ErrMutexNotLocked) {
				log.Panic(errors.Wrapf(err, "failed to obtain registerWebhook db lock"))
			}
			if c.webhookSecret, err = c.loadWebhookSecret(whCtx, db); err != nil {
				if storage.IsErr(err, storage.ErrNotFound) {
					// Wait until at least one instance create WH and store secret
					stdlibtime.Sleep(500 * stdlibtime.Millisecond)
					continue
				}
				log.Panic(errors.Wrapf(err, "failed to load webhook secret while another instance is creating"))
			}
			return
		}
		break
	}
	if cfg.DFNS.WebhookURL != "" {
		if len(c.mustListWebhooks(ctx)) == 0 {
			c.webhookSecret = c.mustRegisterAllEventsWebhook(ctx)
			log.Panic(c.storeWebhookSecret(whCtx, db, c.webhookSecret))
		} else {
			if c.webhookSecret, err = c.loadWebhookSecret(whCtx, db); err != nil {
				log.Panic(errors.Wrapf(err, "failed to read stored webhook secret, must re-create webhook"))
			}
		}
	}

	_ = whLock.Unlock(whCtx)
}

func (c *dfnsClient) storeWebhookSecret(ctx context.Context, db *storage.DB, whSecret string) error {
	_, err := storage.Exec(ctx, db, `INSERT INTO global (key,value) VALUES ('WEBHOOK_SECRET', $1) ON CONFLICT(key) DO
    UPDATE
        SET value = excluded.value
    WHERE global.value != $1 and excluded.value != '';`, whSecret)

	return errors.Wrapf(err, "failed to store webhook secret")
}
func (c *dfnsClient) loadWebhookSecret(ctx context.Context, db *storage.DB) (string, error) {
	res, err := storage.Select[struct {
		Key   string
		Value string
	}](ctx, db, `SELECT * FROM global WHERE key = $1;`, "WEBHOOK_SECRET")
	if err != nil || res == nil {
		if res == nil {
			err = storage.ErrNotFound
		}
		return "", errors.Wrapf(err, "failed to read webhook secret")
	}
	return res[0].Value, nil
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
	header := http.Header{}
	header.Set(appIDHeader, c.cfg.DFNS.AppID)
	status, resp, err := c.doClientCall(ctx, c.serviceAccountClient, "POST", "/webhooks", http.Header{}, jData)
	log.Panic(errors.Wrapf(err, "failed to register webhook"))
	if status != http.StatusOK {
		log.Panic(errors.Errorf("failed to register webhook with status %v body %v", status, string(resp)))
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
	_, jWebhooks, err := c.doClientCall(ctx, c.serviceAccountClient, "GET", "/webhooks", http.Header{}, nil)
	if err != nil {
		log.Panic(errors.Wrapf(err, "failed to list webhooks"))
	}
	var p page[webhook]
	if err = json.UnmarshalContext(ctx, jWebhooks, &p); err != nil {
		log.Panic(errors.Wrapf(err, "failed to unmarshal %v into %#v", string(jWebhooks), p))
	}
	filteredItems := make([]webhook, 0, 1)
	for _, w := range p.Items {
		if w.Url == c.cfg.DFNS.WebhookURL && w.Status == "Enabled" {
			filteredItems = append(filteredItems, w)
		}
	}
	return filteredItems
}

func (c *dfnsClient) ProxyCall(ctx context.Context, rw http.ResponseWriter, req *http.Request) io.Reader {
	respBody := bytes.NewBuffer([]byte{})
	if c.urlRequiresServiceAccountSignature(req.URL.Path) {
		c.serviceAccountProxy.ServeHTTP(&proxyResponseBody{ResponseWriter: rw, Body: respBody}, req)
	} else {
		c.userProxy.ServeHTTP(&proxyResponseBody{ResponseWriter: rw, Body: respBody}, req)
	}
	return respBody
}

func (p *proxyResponseBody) Write(b []byte) (int, error) {
	_, _ = p.Body.Write(b)
	return p.ResponseWriter.Write(b)
}

func (c *dfnsClient) clientCall(ctx context.Context, method, url string, headers http.Header, jsonData []byte) (int, []byte, error) {
	if c.urlRequiresServiceAccountSignature(url) {
		return retry(ctx, func() (status int, body []byte, err error) {
			return c.doClientCall(ctx, c.serviceAccountClient, method, url, headers, jsonData)
		})
	} else {
		return retry(ctx, func() (status int, body []byte, err error) {
			return c.doClientCall(ctx, c.userClient, method, url, headers, jsonData)
		})
	}
}
func (c *dfnsClient) urlRequiresServiceAccountSignature(url string) bool {
	return url == "/auth/registration/delegated" ||
		url == "/auth/login/delegated" ||
		url == "/auth/recover/user/delegated"
}

func (c *dfnsClient) doClientCall(ctx context.Context, httpClient *http.Client, method, relativeUrl string, headers http.Header, jsonData []byte) (int, []byte, error) {
	headers.Set("Content-Type", "application/json")
	fullUrl, err := url.JoinPath(c.cfg.DFNS.BaseURL, relativeUrl)
	if err != nil {
		return 0, nil, errors.Wrapf(err, "failed to build url from %v %v", c.cfg.DFNS.BaseURL, relativeUrl)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, nil, errors.Wrapf(err, "failed to consturct dfns request to %v %v", method, relativeUrl)
	}
	req.Header = headers.Clone()

	response, err := httpClient.Do(req)
	if err != nil {
		if dfnsErr := ParseErrAsDfnsInternalErr(err); dfnsErr != nil {
			var delegatedParsedErr *DfnsInternalError
			if errors.As(dfnsErr, &delegatedParsedErr) {
				delegatedParsedErr.Context = nil
				err = delegatedParsedErr
			}
		}
		return 0, nil, errors.Wrapf(err, "failed to exec dfns request to %v %v", method, relativeUrl)
	}
	defer response.Body.Close()
	bodyData, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, nil, errors.Wrapf(err, "failed to read body data for dfns request to %v %v", method, relativeUrl)
	}
	if response.StatusCode >= http.StatusBadRequest && err == nil {
		err = errors.Errorf("dfns req to %v %v ended up with %v (data: %v)", method, relativeUrl, response.StatusCode, string(bodyData))
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
	resp, err := dfnsCall[struct {
		Username     string `json:"username"`
		CredentialID string `json:"credentialId"`
	}, StartedDelegatedRecovery](ctx, c, params, "POST", "/auth/recover/user/delegated", http.Header{})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to start delegated recovery for username %v credID %v", username, credentialId)
	}
	return resp, nil
}

func dfnsCall[REQ any, RESP any](ctx context.Context, c *dfnsClient, params REQ, method, uri string, headers http.Header) (*RESP, error) {
	postData, err := json.MarshalContext(ctx, params)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to serialize %#v to json")
	}
	status, body, err := c.clientCall(ctx, method, uri, headers, postData)
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

func (c *dfnsClient) GetUser(ctx context.Context, userID string) (*User, error) {
	headers := http.Header{}
	headers.Set(appIDHeader, c.cfg.DFNS.AppID)
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

func (cfg *config) loadCfg(applicationYamlKey string) {
	if fullCfg := os.Getenv("DFNS_CONFIGURATION"); fullCfg != "" {
		var jsonCfg dfnsCfg
		log.Panic(errors.Wrapf(json.Unmarshal([]byte(fullCfg), &jsonCfg), "failed to parse configuration from DFNS_CONFIGURATION env"))
		*cfg = config{DFNS: jsonCfg}
	}
	var yamlCfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &yamlCfg)
	cfg.mustLoadField(&cfg.DFNS.BaseURL, "DFNS_BASE_URL", yamlCfg.DFNS.BaseURL)
	cfg.mustLoadField(&cfg.DFNS.AppID, "DFNS_APP_ID", yamlCfg.DFNS.AppID)
	cfg.mustLoadField(&cfg.DFNS.ServiceKey, "DFNS_SERVICE_KEY", yamlCfg.DFNS.ServiceKey)
	cfg.mustLoadField(&cfg.DFNS.ServiceAccountCredentialID, "DFNS_SERVICE_ACCOUNT_CREDENTIAL_ID", yamlCfg.DFNS.ServiceAccountCredentialID)
	cfg.mustLoadField(&cfg.DFNS.OrganizationID, "DFNS_ORGANIZATION_ID", yamlCfg.DFNS.OrganizationID)

	if cfg.DFNS.ServiceAccountPrivateKey == "" {
		cfg.DFNS.ServiceAccountPrivateKey = yamlCfg.DFNS.ServiceAccountPrivateKey
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
	}
	cfg.DFNS.WebhookURL = yamlCfg.DFNS.WebhookURL
	cfg.DFNS.Auth.Issuer = yamlCfg.DFNS.Auth.Issuer
}

func (*config) mustLoadField(field *string, env, yamlVal string) {
	if field == nil {
		return
	}
	if *field == "" {
		*field = yamlVal
		if *field == "" {
			*field = os.Getenv(env)
			if *field == "" {
				log.Panic(errors.Errorf("%v not set", env))
			}
		}
	}
}
