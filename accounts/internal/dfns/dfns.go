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
	"strconv"
	"strings"
	"sync"
	stdlibtime "time"

	"dario.cat/mergo"
	"github.com/cenkalti/backoff/v4"
	"github.com/dfns/dfns-sdk-go/credentials"
	"github.com/dfns/dfns-sdk-go/dfnsapiclient"
	ethabi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/twilio/twilio-go/client/form"

	"github.com/ice-blockchain/heimdall/server"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func NewDfnsClient(ctx context.Context, db *storage.DB, applicationYamlKey string, coinFeesProvider CoinFeesProvider) DfnsClient {
	var cfg config
	cfg.loadCfg(applicationYamlKey)
	serviceAccountSigner := credentials.NewAsymmetricKeySigner(&credentials.AsymmetricKeySignerConfig{
		PrivateKey: cfg.DFNS.ServiceAccountPrivateKey,
		CredID:     cfg.DFNS.ServiceAccountCredentialID,
	})
	cl := &dfnsClient{
		cfg:                   &cfg,
		serviceAccountSigner:  serviceAccountSigner,
		userClients:           make(map[string]*http.Client),
		serviceAccountClients: make(map[string]*http.Client),
		userMx:                sync.Mutex{},
		serviceAccountMx:      sync.Mutex{},
		proxies:               make(map[string]*httputil.ReverseProxy),
		proxyMx:               sync.Mutex{},
		refreshAuthIssuer:     NewRefreshAuth(applicationYamlKey),
		callbacks:             make(map[string]func(ctx context.Context, now *time.Time, res map[string]any) error),
		tonApi:                mustInitTONClient(ctx, cfg.DFNS.TON.GlobalConfigURL),
		ionApi:                mustInitTONClient(ctx, cfg.DFNS.ION.GlobalConfigURL),
		coinFeesProvider:      coinFeesProvider,
	}
	var err error
	cl.erc20ABI, err = ethabi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		log.Panic(errors.Wrap(err, "failed to parse ABI for ERC20"))
	}
	cl.mustSetupWebhookOrLoadSecret(ctx, db, &cfg)
	if _, hasWebFE := cl.cfg.DFNS.AllowedApplications[cl.cfg.DFNS.WebFEAppID]; !hasWebFE {
		log.Panic(errors.Errorf("webFEAppId is not listed in allowed applications"))
	}
	cl.bodyModifiableCallbacks = map[string]func(ctx context.Context, now *time.Time, res map[string]any, r *http.Response) error{
		"200:" + initDelegatedRegistrationUrl: func(ctx context.Context, now *time.Time, res map[string]any, r *http.Response) error {
			return cl.extendResponseBodyWith(r, res,
				cl.extendChallengeWithRP(),
			)
		},
		"200:" + initLoginUrl: func(ctx context.Context, now *time.Time, res map[string]any, r *http.Response) error {
			return cl.extendResponseBodyWith(r, res,
				cl.extendChallengeWithRP(),
			)
		},
		"200:" + initUserSignatureUrl: func(ctx context.Context, now *time.Time, res map[string]any, r *http.Response) error {
			return cl.extendResponseBodyWith(r, res,
				cl.extendChallengeWithRP(),
			)
		},
		"200:" + completeDelegatedRegistrationUrl: func(ctx context.Context, now *time.Time, res map[string]any, r *http.Response) error {
			userID, username := ExtractUser(res, "username")

			return cl.extendResponseBodyWith(r, res,
				cl.extendRegistrationBodyWithRefreshToken(userID, username),
				extendResponseBodyWithPaymentExtension(),
			)
		},
		"200:" + completeLoginUrl: func(ctx context.Context, now *time.Time, res map[string]any, r *http.Response) error {
			var token string
			if tokenI, hasToken := res["token"]; hasToken {
				token = tokenI.(string)
			}
			if token == "" { //nolint:gosec // .
				return nil
			}
			decodedToken, err := server.Auth(r.Request.Context()).VerifyToken(r.Request.Context(), token)
			if err != nil {
				return errors.Wrap(err, "failed to verify token for just issued user")
			}

			return cl.extendResponseBodyWith(r, res, cl.extendResponseBodyWithRefreshToken(decodedToken.UserID(), decodedToken.Username()))
		},
		"200:" + networkFeesUrl: cl.extendFees(),
		"400:" + networkFeesUrl: cl.extendFees(),
	}
	return cl
}

func (c *dfnsClient) extendFees() func(ctx context.Context, now *time.Time, res map[string]any, r *http.Response) error {
	return func(ctx context.Context, now *time.Time, res map[string]any, r *http.Response) error {
		requestedNetwork := r.Request.URL.Query().Get("network")
		fees := c.coinFeesProvider.GetFees(requestedNetwork)
		if r.StatusCode == 400 {
			if fees == nil {
				return nil
			}
			r.StatusCode = http.StatusOK
			return c.extendResponseBodyWith(r, map[string]any{}, func(ctx context.Context, res map[string]any) error {
				res["network"] = requestedNetwork
				if fees.Fast != nil {
					res["fast"] = fees.Fast
				}
				if fees.Slow != nil {
					res["slow"] = fees.Slow
				}
				if fees.Standard != nil {
					res["standard"] = fees.Standard
				}
				return nil
			})
		}
		if fees != nil {
			return c.extendResponseBodyWith(r, res, func(ctx context.Context, res map[string]any) error {
				b, jerr := json.Marshal(fees)
				if jerr != nil {
					return errors.Wrapf(jerr, "failed to marshal %+v into body", fees)
				}
				var extendedFees map[string]any
				if err := json.Unmarshal(b, &extendedFees); err != nil {
					return errors.Wrapf(jerr, "failed to marshal %+v into body", fees)
				}
				return mergo.Map(&res, extendedFees)
			})
		}
		return c.extendResponseBodyWith(r, res, func(ctx context.Context, res map[string]any) error { return nil })
	}
}

func extendResponseBodyWithPaymentExtension() func(ctx context.Context, res map[string]any) error {
	return func(_ context.Context, res map[string]any) error {
		var ext map[string]any
		if extI, hasExt := res["extensions"]; !hasExt {
			ext = make(map[string]any)
		} else {
			ext = extI.(map[string]any)
		}
		ext["payment"] = map[string]any{
			"isPayment": true,
		}
		res["extensions"] = ext
		return nil
	}
}

func (c *dfnsClient) extendChallengeWithRP() func(ctx context.Context, res map[string]any) error {
	return func(ctx context.Context, res map[string]any) error {
		reqAppID := appID(ctx)
		var rp map[string]any
		if _, hasRP := res["rp"]; hasRP {
			return nil
		}
		rp = map[string]any{
			"id":   c.cfg.DFNS.AllowedApplications[reqAppID].RPID,
			"name": c.cfg.DFNS.AllowedApplications[reqAppID].Name,
		}
		res["rp"] = rp
		return nil
	}
}

func (c *dfnsClient) RegisterPostProxyCallback(url string, cb func(ctx context.Context, now *time.Time, res map[string]any) error) {
	c.callbacks[url] = cb
}

func (c *dfnsClient) serviceAccountClient(appID string) *http.Client {
	c.serviceAccountMx.Lock()
	defer c.serviceAccountMx.Unlock()
	if client, ok := c.serviceAccountClients[appID]; ok {
		return client
	}
	opts, err := dfnsapiclient.NewDfnsAPIOptions(&dfnsapiclient.DfnsAPIConfig{
		AppID:     appID,
		AuthToken: &c.cfg.DFNS.ServiceKey,
		BaseURL:   c.cfg.DFNS.BaseURL,
	}, c.serviceAccountSigner)
	log.Panic(errors.Wrapf(err, "failed to initialize dfns options with serviceAccount signer"))
	serviceClient := dfnsapiclient.CreateDfnsAPIClient(opts)
	c.serviceAccountClients[appID] = serviceClient
	return serviceClient
}
func (c *dfnsClient) userClient(appID string) *http.Client {
	c.userMx.Lock()
	defer c.userMx.Unlock()
	if cl, found := c.userClients[appID]; found {
		return cl
	}
	opts, err := dfnsapiclient.NewDfnsAPIOptions(&dfnsapiclient.DfnsAPIConfig{
		AppID:     appID,
		AuthToken: &c.cfg.DFNS.ServiceKey,
		BaseURL:   c.cfg.DFNS.BaseURL,
	}, nil)
	log.Panic(errors.Wrapf(err, "failed to initialize dfns options for user client"))
	uClient := dfnsapiclient.CreateDfnsAPIClient(opts)
	c.userClients[appID] = uClient
	return uClient
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

func (c *dfnsClient) proxy(typ, appID string) *httputil.ReverseProxy {
	c.proxyMx.Lock()
	defer c.proxyMx.Unlock()
	if p, found := c.proxies[typ+appID]; found {
		return p
	}
	remote, err := url.Parse(c.cfg.DFNS.BaseURL)
	log.Panic(errors.Wrapf(err, "failed to parse dfns base url %v", c.cfg.DFNS.BaseURL))
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Director = c.overwriteHostProxy(remote, appID)
	proxy.ErrorHandler = passErrorInResponse
	proxy.ModifyResponse = c.modifyResponse
	c.proxies[typ+appID] = proxy
	return proxy
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
	status, resp, err := c.doClientCall(ctx, c.serviceAccountClient(c.cfg.DFNS.AppID), "POST", "/webhooks", http.Header{}, jData)
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
	_, jWebhooks, err := c.doClientCall(ctx, c.serviceAccountClient(c.cfg.DFNS.AppID), "GET", "/webhooks", http.Header{}, nil)
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

func (c *dfnsClient) ProxyCall(ctx context.Context, rw http.ResponseWriter, req *http.Request) (status int, responseBody io.Reader) {
	respBody := bytes.NewBuffer([]byte{})
	applicationID := req.Header.Get(clientIDHeader)
	if applicationID == "" {
		applicationID = req.Header.Get(appIDHeader)
		if applicationID == "" {
			applicationID = c.cfg.DFNS.AppID
		}
	}
	req = req.WithContext(context.WithValue(req.Context(), AppIDCtxValue, applicationID))
	userAction := req.Header.Get(userActionHeader)
	if userAction == "" {
		userAction = req.Header.Get(userActionDfnsHeader)
	}
	if userAction != "" {
		req.Header.Set(userActionDfnsHeader, userAction)
	}
	var extendErr error
	var extendErrBody *DfnsInternalError
	switch {
	case req.URL.Path == initDelegatedRegistrationUrl:
		extendErrBody, extendErr = c.updateRegisterReqBodyWithEndUser(req)
	case req.URL.Path == completeDelegatedRegistrationUrl:
		extendErrBody, extendErr = c.updateRegisterReqBodyWithWallets(req)
	case req.URL.Path == delegatedLoginUrl:
		extendErrBody, extendErr = c.exchangeRefreshTokenToUsername(req)
	case req.URL.Path == initUserSignatureUrl:
		extendErrBody, extendErr = c.issueUserActionForSignatureIfManualBroadcastNeeded(req)
	case broadcastTransactionUrlRegexp.MatchString(req.URL.Path):
		rb := &proxyResponseBody{ResponseWriter: rw, Body: respBody}
		if extendErrBody, extendErr = c.checkIfNeedToBroadcastTX(req, rb, applicationID, userAction); extendErr == nil && extendErrBody == nil && respBody.Len() > 0 {
			return http.StatusOK, respBody
		}
	}
	if extendErr != nil && extendErrBody != nil {
		log.Error(errors.Wrapf(extendErr, "failed to update request body during the proxying"))
		rw.Header().Add("Content-Type", "application/json")
		rw.WriteHeader(extendErrBody.HTTPStatus)
		extendErrBody.HTTPStatus = 0
		var resp []byte
		resp, extendErr = json.Marshal(extendErrBody)
		rw.Write(resp)

		return extendErrBody.HTTPStatus, bytes.NewBuffer(resp)
	}
	rb := &proxyResponseBody{ResponseWriter: rw, Body: respBody}
	if c.urlRequiresServiceAccountSignature(req.URL.Path) {
		cl := c.serviceAccountClient(applicationID)
		pr := c.proxy("service", applicationID)
		pr.Transport = cl.Transport
		pr.ServeHTTP(rb, req)
	} else {
		c.proxy("user", applicationID).ServeHTTP(rb, req)
	}
	if rb.Status >= http.StatusBadRequest {
		bodyData, _ := io.ReadAll(respBody)
		log.Error(errors.Wrapf(buildDfnsError(rb.Status, req.Method, bodyData), "dfns req to %v %v ended up with %v", req.Method, req.URL.Path, rb.Status))
	}

	return rb.Status, respBody
}

func (c *dfnsClient) modifyResponse(r *http.Response) error {
	r.Header.Del("Access-Control-Allow-Origin") // Duplicated hea
	now := time.Now()
	callback, hasCallback := c.callbacks[r.Request.URL.Path]
	modifyKey := fmt.Sprintf("%v:%v", r.StatusCode, r.Request.URL.Path)
	bodyModify, hasModify := c.bodyModifiableCallbacks[modifyKey]
	if (r.StatusCode >= http.StatusOK && r.StatusCode < http.StatusBadRequest) || hasModify {
		if hasCallback || hasModify {
			data, res, err := decodeBody(r.Body)
			if err != nil {
				return errors.Wrap(err, "failed to decode response body as json")
			}
			if callback != nil && hasCallback {
				if err = callback(r.Request.Context(), now, res); err != nil {
					return errors.Wrapf(err, "failed to store data in DB on %v", r.Request.URL.Path)
				}
			}
			if bodyModify != nil && hasModify {
				if err = bodyModify(r.Request.Context(), now, res, r); err != nil {
					return errors.Wrapf(err, "failed to modify response data on %v", r.Request.URL.Path)
				}
			} else {
				r.Body = io.NopCloser(bytes.NewBuffer(data))
			}
		}
	}
	return nil
}

func (c *dfnsClient) extendResponseBodyWith(r *http.Response, res map[string]any, extendFns ...func(ctx context.Context, res map[string]any) error) (err error) {
	for _, extend := range extendFns {
		if err = extend(r.Request.Context(), res); err != nil {
			return errors.Wrap(err, "failed to extend response body")
		}
	}

	buf := bytes.NewBuffer(nil)
	err = json.NewEncoder(buf).Encode(res)
	if err != nil {
		return errors.Wrapf(err, "failed to extend response body")
	}
	r.Body = io.NopCloser(buf)
	r.Header["Content-Length"] = []string{fmt.Sprint(buf.Len())}
	return nil
}

func (c *dfnsClient) extendResponseBodyWithRefreshToken(userID, username string) func(ctx context.Context, res map[string]any) error {
	return func(ctx context.Context, res map[string]any) error {
		refresh, err := c.refreshAuthIssuer.IssueRefreshToken(ctx, time.Now(), userID, username)
		if err != nil {
			return errors.Wrapf(err, "failed to issue refresh token for %v %v", userID, username)
		}
		res["refreshToken"] = refresh

		return nil
	}
}
func (c *dfnsClient) extendRegistrationBodyWithRefreshToken(userID, username string) func(ctx context.Context, res map[string]any) error {
	return func(ctx context.Context, res map[string]any) error {
		refresh, err := c.refreshAuthIssuer.IssueRefreshToken(ctx, time.Now(), userID, username)
		if err != nil {
			return errors.Wrapf(err, "failed to issue refresh token for %v %v", userID, username)
		}
		var auth map[string]any
		authI, hasAuth := res["authentication"]
		if !hasAuth {
			auth = map[string]any{}
		} else {
			auth = authI.(map[string]any)
		}
		auth["refreshToken"] = refresh
		res["authentication"] = auth

		return nil
	}
}
func decodeBody(body io.Reader) (respData []byte, jsonData map[string]any, err error) {
	respData, err = io.ReadAll(body)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to read delegated relying party body")
	}
	var res map[string]any
	if err = json.Unmarshal(respData, &res); err != nil {
		return nil, nil, errors.Wrapf(err, "failed to parse json for %v", string(respData))
	}
	return respData, res, nil
}

func extendRequestWith[ReqBody any](req *http.Request, extendFn func(*ReqBody) error) (resp *DfnsInternalError, err error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return &DfnsInternalError{HTTPStatus: http.StatusBadRequest, Message: "failed to read body"},
			errors.Wrapf(err, "failed to extend init login req with orgId: reading body")
	}
	defer req.Body.Close()
	var content ReqBody
	if err = json.Unmarshal(body, &content); err != nil {
		return &DfnsInternalError{HTTPStatus: http.StatusBadRequest, Message: "invalid json"}, errors.Wrapf(err, "invalid body json")
	}
	if err = extendFn(&content); err != nil {
		var errWithStatus *DfnsInternalError
		if errors.As(err, &errWithStatus) {
			return errWithStatus, err
		}
		return &DfnsInternalError{HTTPStatus: http.StatusBadRequest, Message: fmt.Sprintf("validation failed: %v", err.Error())}, errors.Wrap(err, "validation failed")
	}
	body, err = json.Marshal(content)
	if err != nil {
		return &DfnsInternalError{HTTPStatus: http.StatusInternalServerError, Message: "oops, error occured"}, errors.Wrapf(err, "failed to serialize %v", content)
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.ContentLength = int64(len(body))
	req.Body = io.NopCloser(bytes.NewReader(body))

	return nil, nil //nolint:nilnil // .
}

func (c *dfnsClient) updateRegisterReqBodyWithEndUser(req *http.Request) (resp *DfnsInternalError, err error) {
	return extendRequestWith[struct {
		Email string `json:"email"`
		Kind  string `json:"kind"`
	}](req, func(content *struct {
		Email string `json:"email"`
		Kind  string `json:"kind"`
	}) error {
		if !UsernameRegexp.MatchString(content.Email) {
			return errors.Wrapf(ErrInvalidUsername, "must match %v", UsernameRegexp.String())
		}
		content.Kind = "EndUser"
		return nil
	})
}
func (c *dfnsClient) exchangeRefreshTokenToUsername(req *http.Request) (*DfnsInternalError, error) {
	return extendRequestWith[struct {
		RefreshToken string `json:"refreshToken,omitempty"`
		Username     string `json:"username"`
	}](req, func(content *struct {
		RefreshToken string `json:"refreshToken,omitempty"`
		Username     string `json:"username"`
	}) error {
		t, err := c.refreshAuthIssuer.VerifyToken(req.Context(), content.RefreshToken)
		if err != nil {
			return &DfnsInternalError{HTTPStatus: 403, Message: "Invalid refresh token"}
		}
		content.Username = t.Username()
		content.RefreshToken = ""

		return nil
	})
}

func (c *dfnsClient) issueUserActionForWalletCreation(content *struct {
	UserActionPayload    string `json:"userActionPayload,omitempty"`
	UserActionHttpMethod string `json:"userActionHttpMethod"`
	UserActionHttpPath   string `json:"userActionHttpPath"`
	UserActionServerKind string `json:"userActionServerKind"`
}) error {
	if !(content.UserActionHttpMethod == "POST" && content.UserActionHttpPath == "/wallets") {
		return nil
	}
	var input struct {
		Network      string `json:"network"`
		WalletViewID string `json:"walletViewId"`
	}
	var err error
	if err = json.Unmarshal([]byte(content.UserActionPayload), &input); err != nil {
		return errors.Wrapf(err, "invalid json payload %v", content.UserActionPayload)
	}
	var updatedPayload []byte
	if updatedPayload, err = json.Marshal(struct {
		Network string `json:"network"`
		Name    string `json:"name"`
	}{
		Network: input.Network,
		Name:    input.WalletViewID,
	}); err != nil {
		return errors.Wrapf(err, "failed to serialize updated payload %v", content.UserActionPayload)
	}
	content.UserActionPayload = string(updatedPayload)

	return nil
}

func (c *dfnsClient) issueUserActionForSignatureIfManualBroadcastNeeded(req *http.Request) (*DfnsInternalError, error) {
	return extendRequestWith[struct {
		UserActionPayload    string `json:"userActionPayload,omitempty"`
		UserActionHttpMethod string `json:"userActionHttpMethod"`
		UserActionHttpPath   string `json:"userActionHttpPath"`
		UserActionServerKind string `json:"userActionServerKind"`
	}](req, func(content *struct {
		UserActionPayload    string `json:"userActionPayload,omitempty"`
		UserActionHttpMethod string `json:"userActionHttpMethod"`
		UserActionHttpPath   string `json:"userActionHttpPath"`
		UserActionServerKind string `json:"userActionServerKind"`
	}) error {
		if walletIDs := broadcastTransactionUrlRegexp.FindStringSubmatch(content.UserActionHttpPath); walletIDs == nil {
			return c.issueUserActionForWalletCreation(content)
		} else {
			if len(walletIDs) < 2 {
				return errors.Errorf("failed to get extract walletID from url %v %v", content.UserActionHttpPath, walletIDs)
			}
			walletID := walletIDs[1]
			wallet, err := c.GetWallet(req.Context(), walletID)
			if err != nil {
				return errors.Wrapf(err, "failed to get wallet requesting to broadcast tx from %v", walletID)
			}
			_, walletNetwork, _ := ExtractWallet(*wallet)
			walletNetwork = strings.ToLower(walletNetwork)
			if walletNetwork == networkION || walletNetwork == networkIONTestnet || walletNetwork == networkTONTestnet || walletNetwork == networkTON {
				content.UserActionHttpPath = walletSignatureUrl(walletID)
				var txInput struct {
					Transaction string `json:"transaction"`
				}
				if err = json.Unmarshal([]byte(content.UserActionPayload), &txInput); err != nil {
					return errors.Wrapf(err, "invalid json payload %v", content.UserActionPayload)
				}
				var updatedPayload []byte
				if updatedPayload, err = json.Marshal(struct {
					Kind    string `json:"kind"`
					Message string `json:"message"`
				}{
					Kind:    "Message",
					Message: txInput.Transaction,
				}); err != nil {
					return errors.Wrapf(err, "failed to serialize updated payload %v", content.UserActionPayload)
				}
				content.UserActionPayload = string(updatedPayload)
			}
			return nil
		}
	})
}

func (c *dfnsClient) checkIfNeedToBroadcastTX(req *http.Request, rw http.ResponseWriter, clientID, userAction string) (*DfnsInternalError, error) {
	ctx := context.WithValue(req.Context(), AuthHeaderCtxValue, req.Header.Get("Authorization"))
	ctx = context.WithValue(ctx, AppIDCtxValue, clientID)
	ctx = context.WithValue(ctx, UserActionCtxValue, userAction)
	walletID := strings.ReplaceAll(strings.ReplaceAll(req.URL.Path, "/wallets/", ""), "/transactions", "")
	wallet, err := c.GetWallet(req.Context(), walletID)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to get wallet with id %v", walletID))
		return &DfnsInternalError{HTTPStatus: http.StatusInternalServerError, Message: "wallet not found"}, errors.Wrapf(err, "failed to get wallet with id %v", walletID)
	}
	_, walletNetwork, pubkey := ExtractWallet(*wallet)
	broadcastFn, needBroadcast := manualBroadcastNetworks[strings.ToLower(walletNetwork)]
	if !needBroadcast {
		return nil, nil // Continue to normal proxy.
	}
	var transactionBody string
	_, err = extendRequestWith[struct {
		Transaction string `json:"transaction"`
	}](req, func(content *struct {
		Transaction string `json:"transaction"`
	}) error {
		transactionBody = content.Transaction
		return errNoSerialize
	})
	if err != nil && !errors.Is(err, errNoSerialize) {
		return &DfnsInternalError{HTTPStatus: http.StatusInternalServerError, Message: err.Error()}, err
	}
	resp, err := broadcastFn(ctx, c, walletID, pubkey, transactionBody)
	if err != nil {
		return &DfnsInternalError{HTTPStatus: http.StatusInternalServerError, Message: err.Error()}, errors.Wrapf(err, "failed to broadcast transaction")
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return &DfnsInternalError{HTTPStatus: http.StatusInternalServerError, Message: err.Error()}, errors.Wrapf(err, "failed to serialize transaction response")
	}
	rw.Header().Add("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	rw.Write(data)
	return nil, nil
}

func (c *dfnsClient) updateRegisterReqBodyWithWallets(req *http.Request) (resp *DfnsInternalError, err error) {
	return extendRequestWith[struct {
		FirstFactorCredential  map[string]any `json:"firstFactorCredential"`
		SecondFactorCredential map[string]any `json:"secondFactorCredential,omitempty"`
		RecoveryCredential     map[string]any `json:"recoveryCredential,omitempty"`
		Wallets                []struct {
			Network string `json:"network"`
			Name    string `json:"name"`
		} `json:"wallets"`
	}](req, func(content *struct {
		FirstFactorCredential  map[string]any `json:"firstFactorCredential"`
		SecondFactorCredential map[string]any `json:"secondFactorCredential,omitempty"`
		RecoveryCredential     map[string]any `json:"recoveryCredential,omitempty"`
		Wallets                []struct {
			Network string `json:"network"`
			Name    string `json:"name"`
		} `json:"wallets"`
	}) error {
		if len(content.Wallets) == 0 {
			walletNetwork := defaultWalletNetworkMainNet
			if c.cfg.DFNS.TestNet {
				walletNetwork = defaultWalletNetworkTestNet
			}
			content.Wallets = []struct {
				Network string `json:"network"`
				Name    string `json:"name"`
			}{{Network: walletNetwork, Name: defaultWalletName}}
		}
		return nil
	})
}

func (p *proxyResponseBody) Write(b []byte) (int, error) {
	_, _ = p.Body.Write(b)
	return p.ResponseWriter.Write(b)
}
func (p *proxyResponseBody) WriteHeader(status int) {
	p.Status = status
	p.ResponseWriter.WriteHeader(status)
}

func (c *dfnsClient) clientCall(ctx context.Context, method, url string, headers http.Header, jsonData []byte) (int, []byte, error) {
	appID := headers.Get(appIDHeader)
	if appID == "" {
		appID = c.cfg.DFNS.AppID
	}
	if c.urlRequiresServiceAccountSignature(url) {
		return retry(ctx, func() (status int, body []byte, err error) {
			return c.doClientCall(ctx, c.serviceAccountClient(appID), method, url, headers, jsonData)
		})
	} else {
		return retry(ctx, func() (status int, body []byte, err error) {
			return c.doClientCall(ctx, c.userClient(appID), method, url, headers, jsonData)
		})
	}
}
func (c *dfnsClient) urlRequiresServiceAccountSignature(url string) bool {
	return url == "/auth/registration/delegated" ||
		url == "/auth/login/delegated" ||
		url == "/auth/recover/user/delegated"
}

func (c *dfnsClient) doClientCall(ctx context.Context, httpClient *http.Client, method, relativeUrl string, headers http.Header, jsonData []byte) (int, []byte, error) {
	if method != "GET" {
		headers.Set("Content-Type", "application/json")
	}
	client := *httpClient
	if relativeUrl == initUserSignatureUrl || headers.Get(userActionDfnsHeader) != "" {
		client.Transport = http.DefaultTransport
	}
	fullUrl, err := url.JoinPath(c.cfg.DFNS.BaseURL, relativeUrl)
	if err != nil {
		return 0, nil, errors.Wrapf(err, "failed to build url from %v %v", c.cfg.DFNS.BaseURL, relativeUrl)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, nil, errors.Wrapf(err, "failed to consturct dfns request to %v %v", method, relativeUrl)
	}
	req.Header = headers.Clone()
	if method == "GET" {
		req.URL.RawQuery = string(jsonData)
		req.Body = nil
	}
	response, err := client.Do(req)
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
	header := http.Header{}
	header.Set(appIDHeader, appID(ctx))
	resp, err := dfnsCall[struct {
		Username     string `json:"username"`
		CredentialID string `json:"credentialId"`
	}, StartedDelegatedRecovery](ctx, c, &params, "POST", "/auth/recover/user/delegated", header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to start delegated recovery for username %v credID %v", username, credentialId)
	}
	m := map[string]any(*resp)
	m["rp"] = map[string]any{
		"name": c.cfg.DFNS.AllowedApplications[appID(ctx)].Name,
		"id":   c.cfg.DFNS.AllowedApplications[appID(ctx)].RPID,
	}
	*resp = m
	return resp, nil
}

func (c *dfnsClient) GetLoginChallenge(ctx context.Context, username string) (*LoginChallenge, error) {
	params := struct {
		Username string `json:"username"`
		OrgID    string `json:"orgId"`
	}{
		Username: username,
		OrgID:    c.cfg.DFNS.OrganizationID,
	}
	header := http.Header{}
	header.Set(appIDHeader, appID(ctx))
	header.Set(userActionDfnsHeader, "false")
	resp, err := dfnsCall[struct {
		Username string `json:"username"`
		OrgID    string `json:"orgId"`
	}, LoginChallenge](ctx, c, &params, "POST", "/auth/login/init", header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to start login flow for username %v", username)
	}
	m := map[string]any(*resp)
	m["rp"] = map[string]any{
		"name": c.cfg.DFNS.AllowedApplications[appID(ctx)].Name,
		"id":   c.cfg.DFNS.AllowedApplications[appID(ctx)].RPID,
	}
	*resp = m
	return resp, nil
}

func (l *LoginChallenge) PasswordLogin() bool {
	raw := map[string]any(*l)
	allowedCredsI, hasAllowedCreds := raw["allowCredentials"]
	if !hasAllowedCreds {
		return false
	}
	allowedCreds := allowedCredsI.(map[string]any)
	passwordLoginI, hasPasswordLogin := allowedCreds["passwordProtectedKey"]
	if !hasPasswordLogin {
		return false
	}
	passwordLogin := passwordLoginI.([]any)
	webauthnI, hasWebauthn := allowedCreds["webauthn"]
	if !hasWebauthn {
		return len(passwordLogin) > 0
	}
	webauthn := webauthnI.([]any)
	return len(passwordLogin) > 0 && len(webauthn) == 0
}

func dfnsCall[REQ any, RESP any](ctx context.Context, c *dfnsClient, params *REQ, method, uri string, headers http.Header) (*RESP, error) {
	var postData []byte
	if params != nil && method != "GET" {
		var err error
		postData, err = json.MarshalContext(ctx, params)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to serialize %#v to json", params)
		}
	} else if params != nil && method == "GET" {
		s, err := form.EncodeToString(params)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to serialize %#v to formdata", params)
		}
		postData = []byte(s)
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
		return nil, errors.Wrapf(err, "failed to unmarshal response %v for call %v %v", string(body), method, uri)
	}
	return &resp, nil
}

func dfnsAuthHeader(ctx context.Context) string {
	return ctx.Value(AuthHeaderCtxValue).(string)
}
func dfnsUserActionHeader(ctx context.Context) string {
	return ctx.Value(UserActionCtxValue).(string)
}
func appID(ctx context.Context) string {
	return ctx.Value(AppIDCtxValue).(string)
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
	cfg.mustLoadField(&cfg.DFNS.WebFEAppID, "DFNS_WEB_FE_APP_ID", yamlCfg.DFNS.WebFEAppID)
	cfg.mustLoadField(&cfg.DFNS.ServiceKey, "DFNS_SERVICE_KEY", yamlCfg.DFNS.ServiceKey)
	cfg.mustLoadField(&cfg.DFNS.ServiceAccountCredentialID, "DFNS_SERVICE_ACCOUNT_CREDENTIAL_ID", yamlCfg.DFNS.ServiceAccountCredentialID)
	cfg.mustLoadField(&cfg.DFNS.OrganizationID, "DFNS_ORGANIZATION_ID", yamlCfg.DFNS.OrganizationID)

	if cfg.DFNS.ServiceAccountPrivateKey == "" {
		cfg.DFNS.ServiceAccountPrivateKey = yamlCfg.DFNS.ServiceAccountPrivateKey
		if cfg.DFNS.ServiceAccountPrivateKey == "" {
			cfg.DFNS.ServiceAccountPrivateKey = os.Getenv("DFNS_SERVICE_ACCOUNT_PRIVATE_KEY")
			if cfg.DFNS.ServiceAccountPrivateKey == "" {
				pkFile, pkErr := os.Open(os.Getenv("DFNS_SERVICE_ACCOUNT_PRIVATE_KEY_FILE"))
				log.Panic(errors.Wrapf(pkErr, "failed to read dfns private key from file %v", os.Getenv("DFNS_SERVICE_ACCOUNT_PRIVATE_KEY_FILE")))
				defer pkFile.Close()
				var pk []byte
				pk, pkErr = io.ReadAll(pkFile)
				log.Panic(errors.Wrapf(pkErr, "failed to read dfns private key from file %v", os.Getenv("DFNS_SERVICE_ACCOUNT_PRIVATE_KEY_FILE")))
				cfg.DFNS.ServiceAccountPrivateKey = string(pk)
				if cfg.DFNS.ServiceAccountPrivateKey == "" {
					log.Panic(errors.Errorf("dfns service account private key not set"))
				}
			}
		}
	}
	cfg.DFNS.WebhookURL = yamlCfg.DFNS.WebhookURL
	cfg.DFNS.Auth.Issuer = yamlCfg.DFNS.Auth.Issuer
	cfg.DFNS.RefreshAuth.Issuer = yamlCfg.DFNS.RefreshAuth.Issuer
	cfg.DFNS.RefreshAuth.Secret = yamlCfg.DFNS.RefreshAuth.Secret
	cfg.DFNS.RefreshAuth.ExpirationTime = yamlCfg.DFNS.RefreshAuth.ExpirationTime
	cfg.DFNS.TON.GlobalConfigURL = yamlCfg.DFNS.TON.GlobalConfigURL
	cfg.DFNS.ION.GlobalConfigURL = yamlCfg.DFNS.ION.GlobalConfigURL
	cfg.DFNS.TestNet = yamlCfg.DFNS.TestNet
	cfg.DFNS.AllowedApplications = yamlCfg.DFNS.AllowedApplications
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

func (*dfnsClient) overwriteHostProxy(remote *url.URL, appID string) func(req *http.Request) {
	return func(req *http.Request) {
		req.RequestURI = ""
		req.Host = remote.Host
		req.URL.Scheme = remote.Scheme
		req.URL.Host = remote.Host
		req.Header.Set(appIDHeader, appID)
	}
}
