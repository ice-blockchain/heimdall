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

	"github.com/cockroachdb/errors"
	"github.com/dfns/dfns-sdk-go/credentials"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/tvm/cell"

	"github.com/ice-blockchain/heimdall/coins"
	indexer "github.com/ice-blockchain/heimdall/ion-indexer"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/time"
)

type (
	AuthClient interface {
		VerifyToken(ctx context.Context, token string) (server.Token, error)
	}
	CoinFeesProvider interface {
		GetFees(network string) *coins.Fee
	}
	DfnsClient interface {
		ProxyCall(ctx context.Context, rw http.ResponseWriter, r *http.Request) (status int, respBody io.Reader)
		StartDelegatedRecovery(ctx context.Context, username string, credentialId string) (*StartedDelegatedRecovery, error)
		GetLoginChallenge(ctx context.Context, username string) (*LoginChallenge, error)
		InitRegistration(ctx context.Context, identityKeyName string) (*RegistrationChallenge, error)
		CompleteRegistrationWithWallets(ctx context.Context, credentials *Credentials) (CompletedRegistration, error)
		GetUser(ctx context.Context, userID string) (*User, error)
		VerifyWebhookSecret(fromWebhook string) bool
		RegisterPostProxyCallback(url string, cb func(req *http.Request, now *time.Time, res map[string]any) error)
		ListWallets(ctx context.Context, userID string) ([]Wallet, error)
		GetWallet(ctx context.Context, userID string) (*Wallet, error)
		CreateWallet(ctx context.Context, network, name string) (*Wallet, error)
		ListAssets(ctx context.Context, walletID string) (*Assets, error)
		ListNFTs(ctx context.Context, walletID string) (*NFTs, error)
		GetWalletHistory(ctx context.Context, walletID, paginationToken string, limit uint) (*WalletHistory, error)
		SecurePaymentConfirmation(ctx context.Context, userID, network string, wallet Wallet, body map[string]string) (tmplData any, err error)
	}
	RefreshAuth interface {
		AuthClient
		IssueRefreshToken(ctx context.Context, now *time.Time, userID, username string) (string, error)
	}
	StartedDelegatedRecovery map[string]any
	User                     map[string]any
	Wallet                   map[string]any
	Asset                    = indexer.Asset
	NFT                      = coins.WalletNFT
	LoginChallenge           map[string]any
	RegistrationChallenge    map[string]any
	CompletedRegistration    map[string]any
	Assets                   struct {
		Assets   []Asset `json:"assets"`
		Network  string  `json:"network"`
		WalletID string  `json:"walletId"`
	}
	NFTs struct {
		NFTs     []NFT  `json:"nfts"`
		Network  string `json:"network"`
		WalletID string `json:"walletId"`
	}

	WalletHistory struct {
		Items         []WalletHistoryItem `json:"items"`
		Network       string              `json:"network"`
		WalletID      string              `json:"walletId"`
		NextPageToken *string             `json:"nextPageToken,omitempty"`
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

	Credentials struct {
		FirstFactorCredential  map[string]any `json:"firstFactorCredential"`
		SecondFactorCredential map[string]any `json:"secondFactorCredential,omitempty"`
		RecoveryCredential     map[string]any `json:"recoveryCredential,omitempty"`
		EarlyAccessEmail       string         `json:"earlyAccessEmail,omitempty"`
		Wallets                []struct {
			Network string `json:"network"`
			Name    string `json:"name"`
		} `json:"wallets"`
	}

	WalletHistoryItem = indexer.WalletHistoryItem
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
	initCredentialCreationUrl        = "/auth/credentials/init"
	completeUserSignatureUrl         = "/auth/action"
	broadcastTransactionUrl          = "/wallets/(wa-[^/]+)/transactions"
	networkFeesUrl                   = "/networks/fees"

	DefaultWalletNetworkTestNet               = "IonTestnet"
	DefaultWalletNetworkMainNet               = "Ion"
	DefaultWalletNetworkMainNetForOldAccounts = "Ton"
	DefaultWalletNetworkTestNetForOldAccounts = "TonTestnet"
	defaultWalletName                         = "main"

	networkTON                = "ton"
	networkTONTestnet         = "tontestnet"
	networkION                = "ion"
	networkIONTestnet         = "iontestnet"
	erc20ABI                  = `[{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}]`
	ErrMessageNFTNotSupported = `does not support NFT balances`
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
		callbacks               map[string][]func(req *http.Request, now *time.Time, res map[string]any) error
		bodyModifiableCallbacks map[string]func(ctx context.Context, now *time.Time, res map[string]any, r *http.Response) error
		webhookSecret           string
		userMx                  sync.Mutex
		serviceAccountMx        sync.Mutex
		proxyMx                 sync.Mutex
		tonApi                  ton.APIClientWrapped
		ionApi                  ton.APIClientWrapped
		erc20ABI                abi.ABI
		coinFeesProvider        CoinFeesProvider
	}
	config struct {
		DFNS dfnsCfg `yaml:"delegated_relying_party" mapstructure:"delegated_relying_party"`
	}
	dfnsCfg struct {
		ServiceKey                 string `yaml:"serviceKey" mapstructure:"serviceKey" json:"serviceKey"`
		ServiceAccountCredentialID string `yaml:"serviceAccountCredentialId" mapstructure:"serviceAccountCredentialId" json:"serviceAccountCredentialId"`
		ServiceAccountPrivateKey   string `yaml:"serviceAccountPrivateKey" mapstructure:"serviceAccountPrivateKey" json:"serviceAccountPrivateKey"`
		WebFEAppID                 string `yaml:"webFEAppId" mapstructure:"webFEAppId" json:"webFEAppId"` // AppID of web FE, used in payments html
		OrganizationID             string `yaml:"organizationId" mapstructure:"organizationId" json:"organizationId"`
		BaseURL                    string `yaml:"baseUrl" mapstructure:"baseUrl" json:"baseUrl"`
		WebhookURL                 string `yaml:"webhookUrl" mapstructure:"webhookUrl"`
		AllowedApplications        map[string]struct {
			RPID   string `yaml:"rpId" mapstructure:"rpId"`
			Origin string `yaml:"origin" mapstructure:"origin"`
			Name   string `yaml:"name" mapstructure:"name"`
		} `yaml:"allowedApplications" mapstructure:"allowedApplications"`
		Auth struct {
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
		ION struct {
			GlobalConfigURL string `yaml:"global-config-url" mapstructure:"global-config-url"`
		} `yaml:"ion" mapstructure:"ion"`
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
		decimals    int
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
		networkTON: func(ctx context.Context, c *dfnsClient, walletID, walletPubKey, txPayload string) (*BroadcastTxResponse, error) {
			return c.broadcastTONTransaction(ctx, c.tonApi, networkTON, walletID, walletPubKey, txPayload)
		},
		networkTONTestnet: func(ctx context.Context, c *dfnsClient, walletID, walletPubKey, txPayload string) (*BroadcastTxResponse, error) {
			return c.broadcastTONTransaction(ctx, c.tonApi, networkTON, walletID, walletPubKey, txPayload)
		},
		networkIONTestnet: func(ctx context.Context, c *dfnsClient, walletID, walletPubKey, txPayload string) (*BroadcastTxResponse, error) {
			return c.broadcastTONTransaction(ctx, c.ionApi, networkION, walletID, walletPubKey, txPayload)
		},
		networkION: func(ctx context.Context, c *dfnsClient, walletID, walletPubKey, txPayload string) (*BroadcastTxResponse, error) {
			return c.broadcastTONTransaction(ctx, c.ionApi, networkION, walletID, walletPubKey, txPayload)
		},
	}
	errNoSerialize = errors.New("no serialize")
)
