// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"crypto/ed25519"
	"net/url"
	stdlibtime "time"

	"github.com/cenkalti/backoff/v4"
	"github.com/dfns/dfns-sdk-go/dfnsapiclient"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func NewDfnsTokenAuth(ctx context.Context, applicationYamlKey string) AuthClient {
	var cfg config
	cfg.loadCfg(applicationYamlKey)
	cache := jwk.NewCache(ctx)
	jwksFullUrl, err := url.JoinPath(cfg.DFNS.BaseURL, jwksUrl)
	log.Panic(errors.Wrapf(err, "failed to build JWKS url from %v %v", cfg.DFNS.BaseURL, jwksUrl))
	opts, err := dfnsapiclient.NewDfnsAPIOptions(&dfnsapiclient.DfnsAPIConfig{
		BaseURL: cfg.DFNS.BaseURL,
	}, nil)
	log.Panic(errors.Wrapf(err, "dfns/auth: failed to init dfns options"))

	log.Panic(errors.Wrapf(cache.Register(
		jwksFullUrl,
		jwk.WithMinRefreshInterval(1*stdlibtime.Minute),
		jwk.WithHTTPClient(dfnsapiclient.CreateDfnsAPIClient(opts)),
	),
		"failed to register jwks url %v", jwksFullUrl))
	_, err = cache.Refresh(ctx, jwksFullUrl)
	log.Panic(errors.Wrapf(err, "failed to fetch dfns key set from %v", jwksUrl))
	return &dfnsAuth{dfnsPubKeys: cache, cfg: &cfg}
}

func (a *dfnsAuth) VerifyToken(ctx context.Context, tokenStr string) (server.Token, error) {
	var claims jwt.MapClaims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (res interface{}, err error) {
		var edDsaKey ed25519.PublicKey
		err = backoff.RetryNotify(
			func() error {
				jwksFullUrl, _ := url.JoinPath(a.cfg.DFNS.BaseURL, jwksUrl)
				keySet, kerr := a.dfnsPubKeys.Get(ctx, jwksFullUrl)
				if kerr != nil {
					return errors.Wrapf(kerr, "failed to get cached dfns pub keys for %v", jwksUrl)
				}
				for it := keySet.Keys(ctx); it.Next(ctx); {
					k := it.Pair().Value.(jwk.Key)
					var pubKey ed25519.PublicKey
					if k.Raw(&pubKey) == nil {
						edDsaKey = pubKey
						break
					}
				}
				if len(edDsaKey) == 0 {
					return errors.Errorf("cannot detect Ed25519 key in jwks %v", jwksUrl)
				}
				return nil
			},
			backoff.WithContext(&backoff.ExponentialBackOff{
				InitialInterval:     10 * stdlibtime.Millisecond, //nolint:mnd,gomnd // .
				RandomizationFactor: 0.5,                         //nolint:mnd,gomnd // .
				Multiplier:          2.5,                         //nolint:mnd,gomnd // .
				MaxInterval:         1 * stdlibtime.Second,
				MaxElapsedTime:      requestDeadline,
				Stop:                backoff.Stop,
				Clock:               backoff.SystemClock,
			}, ctx),
			func(e error, next stdlibtime.Duration) {
				log.Error(errors.Wrapf(e, "call for jwks %v failed. retrying in %v... ", jwksUrl, next))
			})
		return edDsaKey, err
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, errors.Wrapf(ErrExpiredToken, "expired or not valid yet token")
		}
		return nil, errors.Wrapf(err, "failed to parse token %v as JWT", tokenStr)
	}
	if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok || token.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
		return nil, errors.Errorf("unexpected signing method:%v", token.Header["alg"])
	}
	if iss, iErr := token.Claims.GetIssuer(); iErr != nil || (iss != a.cfg.DFNS.Auth.Issuer) {
		return nil, errors.Wrapf(ErrInvalidToken, "invalid issuer: %v", iss)
	}
	if sub, sErr := token.Claims.GetSubject(); sErr != nil || (sub != a.cfg.DFNS.OrganizationID) {
		return nil, errors.Wrapf(ErrInvalidToken, "invalid organization: %v", sub)
	}
	meta, hasMeta := claims["https://custom/app_metadata"]
	if !hasMeta {
		log.Panic(errors.Errorf("no \"https://custom/app_metadata\" in token claims, cannot get userID, unsupported token: %v", tokenStr))
	}
	userID, hasUserID := meta.(map[string]any)["userId"]
	if !hasUserID {
		log.Panic(errors.Errorf("no userId in app_metadata in token claims, cannot get userID, unsupported token: %v", tokenStr))
	}
	return &dfnsToken{
		userID:   userID.(string),
		username: claims["https://custom/username"].(string),
	}, nil
}

func (t *dfnsToken) Username() string {
	return t.username
}
func (t *dfnsToken) UserID() string {
	return t.userID
}

func NewRefreshAuth(applicationYamlKey string) RefreshAuth {
	var cfg config
	cfg.loadCfg(applicationYamlKey)
	if cfg.DFNS.RefreshAuth.ExpirationTime == 0 {
		log.Panic(errors.New("expiration time for refreshToken not set"))
	}
	if cfg.DFNS.RefreshAuth.Secret == "" {
		log.Panic(errors.New("secret for refreshToken not set"))
	}
	return &refreshAuth{
		cfg: &cfg,
		signToken: func(token *jwt.Token) (string, error) {
			return token.SignedString([]byte(cfg.DFNS.RefreshAuth.Secret))
		},
	}
}

func (t *refreshToken) Username() string {
	return t.UserName
}
func (t *refreshToken) UserID() string {
	return t.UserId
}

func (a *refreshAuth) IssueRefreshToken(ctx context.Context, now *time.Time, userID, username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshToken{
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    a.cfg.DFNS.RefreshAuth.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(now.Add(a.cfg.DFNS.RefreshAuth.ExpirationTime)),
			NotBefore: jwt.NewNumericDate(*now.Time),
			IssuedAt:  jwt.NewNumericDate(*now.Time),
		},
		UserId:   userID,
		UserName: username,
	})
	refresh, err := a.signToken(token)

	return refresh, errors.Wrapf(err, "failed to generate refresh token for userID:%v, username:%v", userID, username)
}

func (a *refreshAuth) VerifyToken(ctx context.Context, token string) (server.Token, error) {
	var res refreshToken
	if _, err := jwt.ParseWithClaims(token, &res, a.verify()); err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, errors.Wrapf(server.ErrExpiredToken, "expired or not valid yet token")
		}
		return nil, errors.Wrapf(err, "invalid token:%v", token)
	}
	return &res, nil
}

func (a *refreshAuth) verify() func(token *jwt.Token) (any, error) {
	return func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || token.Method.Alg() != jwt.SigningMethodHS256.Name {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		iss, err := token.Claims.GetIssuer()
		invalidIssuer := (iss != a.cfg.DFNS.RefreshAuth.Issuer)
		if err != nil || invalidIssuer {
			return nil, errors.Wrapf(server.ErrInvalidToken, "invalid issuer:%v", iss)
		}

		return []byte(a.cfg.DFNS.RefreshAuth.Secret), nil
	}
}
