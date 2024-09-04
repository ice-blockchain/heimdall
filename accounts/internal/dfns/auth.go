// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"crypto/ed25519"
	"net/url"
	stdlibtime "time"

	"github.com/dfns/dfns-sdk-go/dfnsapiclient"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/log"
)

func NewDfnsTokenAuth(ctx context.Context, applicationYamlKey string) AuthClient {
	var cfg config
	cfg.loadCfg(applicationYamlKey)
	cache := jwk.NewCache(ctx)
	jwksFullUrl, err := url.JoinPath(cfg.DFNS.BaseURL, jwksUrl)
	log.Panic(errors.Wrapf(err, "failed to build JWKS url from %v %v", cfg.DFNS.BaseURL, jwksUrl))
	opts, err := dfnsapiclient.NewDfnsAPIOptions(&dfnsapiclient.DfnsAPIConfig{
		AppID:   cfg.DFNS.AppID,
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
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
		jwksFullUrl, _ := url.JoinPath(a.cfg.DFNS.BaseURL, jwksUrl)
		keySet, err := a.dfnsPubKeys.Get(ctx, jwksFullUrl)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get cached dfns pub keys for %v", jwksUrl)
		}
		var edDsaKey ed25519.PublicKey
		for it := keySet.Keys(ctx); it.Next(ctx); {
			k := it.Pair().Value.(jwk.Key)
			var pubKey ed25519.PublicKey
			if k.Raw(&pubKey) == nil {
				edDsaKey = pubKey
				break
			}
		}
		if len(edDsaKey) == 0 {
			log.Panic(errors.Errorf("cannot detect Ed25519 key in jwks %v", jwksUrl))
		}
		return edDsaKey, nil
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
