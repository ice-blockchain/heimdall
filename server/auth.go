// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"crypto/ed25519"
	"os"
	stdlibtime "time"

	"github.com/dfns/dfns-sdk-go/dfnsapiclient"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/log"
)

func newDfnsTokenAuth(ctx context.Context) AuthClient {
	cache := jwk.NewCache(ctx)
	jwksUrl := cfg.AuthDfns.BaseURL + jwksSuffix
	if cfg.AuthDfns.AppID == "" {
		cfg.AuthDfns.AppID = os.Getenv("DFNS_APP_ID")
	}
	if cfg.AuthDfns.OrganizationID == "" {
		cfg.AuthDfns.OrganizationID = os.Getenv("DFNS_ORGANIZATION_ID")
	}
	opts, err := dfnsapiclient.NewDfnsAPIOptions(&dfnsapiclient.DfnsAPIConfig{
		AppID:   cfg.AuthDfns.AppID,
		BaseURL: cfg.AuthDfns.BaseURL,
	}, nil)
	log.Panic(errors.Wrapf(err, "dfns/auth: failed to init dfns options"))

	log.Panic(errors.Wrapf(cache.Register(
		jwksUrl,
		jwk.WithMinRefreshInterval(1*stdlibtime.Minute),
		jwk.WithHTTPClient(dfnsapiclient.CreateDfnsAPIClient(opts)),
	),
		"failed to register jwks url %v", jwksUrl))
	_, err = cache.Refresh(ctx, jwksUrl)
	log.Panic(errors.Wrapf(err, "failed to fetch dfns key set from %v", jwksUrl))
	return &dfnsAuth{dfnsPubKeys: cache}
}

func (a *dfnsAuth) VerifyToken(ctx context.Context, tokenStr string) (*Token, error) {
	var claims jwt.MapClaims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
		jwksUrl := cfg.AuthDfns.BaseURL + jwksSuffix
		keySet, err := a.dfnsPubKeys.Get(ctx, jwksUrl)
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
	if iss, iErr := token.Claims.GetIssuer(); iErr != nil || (iss != cfg.AuthDfns.Issuer) {
		return nil, errors.Wrapf(ErrInvalidToken, "invalid issuer: %v", iss)
	}
	if sub, sErr := token.Claims.GetSubject(); cfg.AuthDfns.OrganizationID != "" && (sErr != nil || (sub != cfg.AuthDfns.OrganizationID)) {
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
	return &Token{
		UserID:   userID.(string),
		Username: claims["https://custom/username"].(string),
	}, nil
}
