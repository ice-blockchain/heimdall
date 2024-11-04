// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"regexp"
	"sync"
	stdlibtime "time"

	"github.com/dfns/dfns-sdk-go/credentials"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/tvm/cell"

	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/time"
)

type (
	AuthClient interface {
		VerifyToken(ctx context.Context, token string) (server.Token, error)
	}
	DfnsClient interface {
		ProxyCall(ctx context.Context, rw http.ResponseWriter, r *http.Request) (status int, respBody io.Reader)
		StartDelegatedRecovery(ctx context.Context, username string, credentialId string) (*StartedDelegatedRecovery, error)
		GetUser(ctx context.Context, userID string) (*User, error)
		VerifyWebhookSecret(fromWebhook string) bool
		RegisterPostProxyCallback(url string, cb func(ctx context.Context, now *time.Time, res map[string]any) error)
		ListWallets(ctx context.Context, userID string) ([]Wallet, error)
		GetWallet(ctx context.Context, userID string) (*Wallet, error)
		ListAssets(ctx context.Context, walletID string) (*Assets, error)
		SecurePaymentConfirmation(ctx context.Context, userID, network string, wallet Wallet, body map[string]any) (tmplData any, err error)
	}
	RefreshAuth interface {
		AuthClient
		IssueRefreshToken(ctx context.Context, now *time.Time, userID, username string) (string, error)
	}
	StartedDelegatedRecovery map[string]any
	User                     map[string]any
	Wallet                   map[string]any
	Asset                    map[string]any
	Assets                   struct {
		Assets   []Asset `json:"assets"`
		Network  string  `json:"network"`
		WalletID string  `json:"walletId"`
	}
	BroadcastTxResponse struct {
		Id        string `json:"id"`
		WalletId  string `json:"walletId"`
		Network   string `json:"network"`
		Requester struct {
			UserId string `json:"userId"`
			AppId  string `json:"appId"`
		} `json:"requester"`
		RequestBody struct {
			Kind        string `json:"kind"`
			Transaction string `json:"transaction"`
		} `json:"requestBody"`
		Status          string          `json:"status"`
		TxHash          string          `json:"txHash"`
		DateRequested   stdlibtime.Time `json:"dateRequested"`
		DateBroadcasted stdlibtime.Time `json:"dateBroadcasted"`
	}
)

const (
	AuthHeaderCtxValue               = "authHeaderCtxValue"
	AppIDCtxValue                    = "XDfnsAppIDCtxValue"
	UserActionCtxValue               = "XDfnsUserActionCtxValue"
	appIDHeader                      = "X-Dfns-Appid"
	userActionDfnsHeader             = "X-Dfns-Useraction"
	authDfnsHeader                   = "Authorization"
	userActionHeader                 = "X-Useraction"
	clientIDHeader                   = "X-Client-Id"
	requestDeadline                  = 25 * stdlibtime.Second
	jwksUrl                          = "/.well-known/jwks.json"
	initLoginUrl                     = "/auth/login/init"
	completeLoginUrl                 = "/auth/login"
	initDelegatedRegistrationUrl     = "/auth/registration/delegated"
	completeDelegatedRegistrationUrl = "/auth/registration/enduser"
	delegatedLoginUrl                = "/auth/login/delegated" // Refresh token actually.
	initUserSignatureUrl             = "/auth/action/init"
	completeUserSignatureUrl         = "/auth/action"
	broadcastTransactionUrl          = "/wallets/wa-[-A-z0-9]{28}/transactions"

	defaultWalletNetwork = "Ton"
	defaultWalletName    = "main"

	erc20ABI = `[{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}]`
)

var (
	ErrInvalidToken    = server.ErrInvalidToken
	ErrExpiredToken    = server.ErrExpiredToken
	ErrInvalidUsername = errors.New("invalid username")
	ErrRaceCondition   = errors.New("race condition")
	UsernameRegexp     = regexp.MustCompile("^[a-z0-9._-]+$")
)

type (
	dfnsClient struct {
		refreshAuthIssuer       RefreshAuth
		cfg                     *config
		serviceAccountSigner    *credentials.AsymmetricKeySigner
		userClients             map[string]*http.Client
		serviceAccountClients   map[string]*http.Client
		proxies                 map[string]*httputil.ReverseProxy
		callbacks               map[string]func(ctx context.Context, now *time.Time, res map[string]any) error
		bodyModifiableCallbacks map[string]func(ctx context.Context, now *time.Time, res map[string]any, r *http.Response) error
		webhookSecret           string
		webFE                   *application
		userMx                  sync.Mutex
		serviceAccountMx        sync.Mutex
		proxyMx                 sync.Mutex
		tonApi                  ton.APIClientWrapped
		erc20ABI                abi.ABI
	}
	config struct {
		DFNS dfnsCfg `yaml:"delegated_relying_party" mapstructure:"delegated_relying_party"`
	}
	dfnsCfg struct {
		ServiceKey                 string `yaml:"serviceKey" mapstructure:"serviceKey" json:"serviceKey"`
		ServiceAccountCredentialID string `yaml:"serviceAccountCredentialId" mapstructure:"serviceAccountCredentialId" json:"serviceAccountCredentialId"`
		ServiceAccountPrivateKey   string `yaml:"serviceAccountPrivateKey" mapstructure:"serviceAccountPrivateKey" json:"serviceAccountPrivateKey"`
		AppID                      string `yaml:"appId" mapstructure:"appId" json:"appId"`
		WebFEAppID                 string `yaml:"webFEAppId" mapstructure:"webFEAppId" json:"webFEAppId"` // AppID of web FE, used in payments html
		OrganizationID             string `yaml:"organizationId" mapstructure:"organizationId" json:"organizationId"`
		BaseURL                    string `yaml:"baseUrl" mapstructure:"baseUrl" json:"baseUrl"`
		WebhookURL                 string `yaml:"webhookUrl" mapstructure:"webhookUrl"`
		Auth                       struct {
			Issuer string `yaml:"issuer" mapstructure:"issuer"`
		} `yaml:"auth" mapstructure:"auth"`
		RefreshAuth struct {
			Issuer         string              `yaml:"issuer" mapstructure:"issuer"`
			Secret         string              `yaml:"secret" mapstructure:"secret"`
			ExpirationTime stdlibtime.Duration `yaml:"expirationTime" mapstructure:"expirationTime"`
		} `yaml:"refreshToken" mapstructure:"refreshToken"`
		TestNet bool `yaml:"testNet" mapstructure:"testNet"`
		TON     struct {
			GlobalConfigURL string `yaml:"global-config-url" mapstructure:"global-config-url"`
		} `yaml:"ton" mapstructure:"ton"`
	}

	webhook struct {
		DateCreated *time.Time `json:"dateCreated"`
		DateUpdated *time.Time `json:"dateUpdated"`
		Secret      *string    `json:"secret"`
		Id          string     `json:"id"`
		Url         string     `json:"url"`
		Description string     `json:"description"`
		Status      string     `json:"status"`
		Events      []string   `json:"events"`
	}
	application struct {
		AppID          string `json:"appId"`
		ExpectedRPId   string `json:"expectedRpId"`
		ExpectedOrigin string `json:"expectedOrigin"`
		IsActive       bool   `json:"isActive"`
	}
	page[T any] struct {
		Items         []T     `json:"items"`
		NextPageToken *string `json:"nextPageToken"`
	}
	dfnsAuth struct {
		dfnsPubKeys *jwk.Cache
		cfg         *config
	}
	dfnsToken struct {
		userID   string
		username string
	}
	proxyResponseBody struct {
		http.ResponseWriter
		Body   io.Writer
		Status int
	}
	refreshToken struct {
		*jwt.RegisteredClaims
		UserId   string `json:"userId"`
		UserName string `json:"username"`
	}
	refreshAuth struct {
		cfg       *config
		signToken func(token *jwt.Token) (string, error)
	}
	signatureChallenge = map[string]any
	signatureResult    struct {
		ID        string `json:"id"`
		Requester struct {
			UserID string `json:"userId"`
		} `json:"requester"`
		Signature struct {
			R       string `json:"r"`
			S       string `json:"s"`
			Encoded string `json:"encoded"`
		} `json:"signature"`
	}
	transferTransaction struct {
		ReceiverAddress string
		Sender          string
		Amount          string
		Token           string
		Network         *network
	}
	network struct {
		NativeToken string
		Icon        string
	}
	tonTransactionInputV4R2 struct {
		WalletID        uint32               `tlb:"## 32"`
		TTL             uint64               `tlb:"## 32"`
		Seq             uint64               `tlb:"## 32"`
		OpCode          uint8                `tlb:"## 8"`
		Mode            uint8                `tlb:"## 8"`
		InternalMessage *tlb.InternalMessage `tlb:"^"`
	}
	tonTransactionInputV5 struct {
		_                 tlb.Magic  `tlb:"#7369676e"`
		WalletID          uint32     `tlb:"## 32"`
		TTL               uint32     `tlb:"## 32"`
		Seq               uint32     `tlb:"## 32"`
		Actions           *v5actions `tlb:"^"`
		W5ExtendedActions *cell.Cell `tlb:"maybe ."`
	}
	v5actions []v5action
	v5action  struct {
		_    tlb.Magic            `tlb:"#0ec3c86d"`
		Mode uint8                `tlb:"## 8"`
		Msg  *tlb.InternalMessage `tlb:"^"`
	}
	tonTx interface {
		GetWalletID() uint32
		GetSeq() uint64
		EmbedSignature(signature, walletPubkey []byte, initialized bool, networkID int32) (*tlb.ExternalMessage, *cell.Cell, error)
	}
)

var (
	broadcastTransactionUrlRegexp = regexp.MustCompile(broadcastTransactionUrl)
	manualBroadcastNetworks       = map[string]func(ctx context.Context, c *dfnsClient, walletID, walletPubKey, txPayload string) (*BroadcastTxResponse, error){
		"ton": func(ctx context.Context, c *dfnsClient, walletID, walletPubKey, txPayload string) (*BroadcastTxResponse, error) {
			return c.broadcastTONTransaction(ctx, walletID, walletPubKey, txPayload)
		},
	}
	errNoSerialize = errors.New("no serialize")
)
