// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"

	"github.com/cockroachdb/errors"
	"github.com/gin-gonic/gin"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/terror"
)

type (
	delegatedErrorResponse struct {
		err   error          `json:"-"`
		Data  map[string]any `json:"data,omitempty"`
		Error errMessage     `json:"error"`
	}
	errMessage struct {
		Message string `json:"message"`
	}
)

func (d *delegatedErrorResponse) InternalErr() error {
	return d.err
}
func buildDelegatedErrorResponse(status int, err error, code string, data ...map[string]any) *server.ErrResponse[*delegatedErrorResponse] {
	msg := err.Error()
	if len(code) > 0 {
		msg = code
	}

	resp := &server.ErrResponse[*delegatedErrorResponse]{
		Data:    &delegatedErrorResponse{Error: errMessage{Message: msg}, err: err},
		Headers: nil,
		Code:    status,
	}
	if len(data) > 0 {
		resp.Data.Data = data[0]
	}
	return resp
}

func (s *service) setupDelegatedRPProxyRoutes(router *server.Router) {
	templ := template.Must(template.New("").ParseFS(templates, "templates/*.html"))
	router.SetHTMLTemplate(templ)
	router.NoRoute(s.proxyToDelegatedRP(true))
	router.NoMethod(s.proxyToDelegatedRP(true))
	router.
		POST("auth/recover/user/delegated", server.RootHandler(s.StartDelegatedRecovery)).
		GET("wallets/:walletId/nfts", server.RootHandler(s.GetNFTs)).
		POST("/auth/login/delegated", s.proxyToDelegatedRP(true)).
		POST("/v1/webhooks/dfns/events", server.RootHandler(s.EventWebhookFromDelegatedRP)).
		GET("/.well-known/apple-app-site-association", server.RootHandler(s.AppleAppSiteAssociation)).
		GET("/.well-known/assetlinks.json", server.RootHandler(s.AssetLinks)).
		GET("/v1/users/:userIdOrMasterKey/wallets/:walletId/secure-payment-confirmations", s.securePaymentConfirmation()).
		POST("/auth/login/init", server.RootHandler(s.GetLoginChallenge)).
		POST("/auth/registration/enduser", server.RootHandler(s.CompleteRegistration)).
		POST("/auth/registration/delegated", server.RootHandler(s.InitRegistration)).
		GET("/v1/early-access-users", server.RootHandler(s.EarlyAccessAvailable)).
		POST("/wallets", server.RootHandler(s.CreateWallet))
}

func (s *service) proxyToDelegatedRP(allowUnauthorized bool) func(*gin.Context) {
	return func(ginCtx *gin.Context) {
		ctx, cancel := context.WithTimeout(ginCtx.Request.Context(), proxyTimeout)
		defer cancel()
		if _, err := server.Authorize(ctx, ginCtx, allowUnauthorized); err != nil {
			ginCtx.JSON(err.Code, &delegatedErrorResponse{Error: errMessage{Message: err.Data.Code}, err: err.Data.InternalErr()})
			return
		}
		s.accounts.ProxyDelegatedRelyingParty(ctx, ginCtx.Writer, ginCtx.Request)
	}
}

func (s *service) securePaymentConfirmation() func(*gin.Context) {
	return func(ginCtx *gin.Context) {
		ctx, cancel := context.WithTimeout(ginCtx.Request.Context(), proxyTimeout)
		defer cancel()
		body := make(map[string]string, 0)
		if err := ginCtx.ShouldBindQuery(&body); err != nil {
			ginCtx.JSON(http.StatusUnprocessableEntity, &delegatedErrorResponse{Error: errMessage{Message: invalidPropertiesErrorCode}})
			return
		}
		auth, _ := ginCtx.GetQuery("authorization")
		if _, err := server.AuthorizeWithCustomAuthStore(ctx, ginCtx, false, func(gCtx *gin.Context) string {
			return auth
		}); err != nil {
			ginCtx.JSON(err.Code, &delegatedErrorResponse{Error: errMessage{Message: err.Data.Code}, err: err.Data.InternalErr()})
			return
		}
		clientID, _ := ginCtx.GetQuery("clientID")
		ctx = withAppID(ctx, clientID)
		ctx = withAuth(ctx, fmt.Sprintf("Bearer %v", auth))
		delete(body, "clientID")
		delete(body, "authorization")
		delete(body, "callbackUrl")
		walletId := ginCtx.Param("walletId")
		if walletId == "" {
			ginCtx.JSON(http.StatusUnprocessableEntity, &delegatedErrorResponse{Error: errMessage{Message: invalidPropertiesErrorCode}})
			return
		}
		data, err := s.accounts.SecurePaymentConfirmation(ctx, ginCtx.Param("userIdOrMasterKey"), walletId, body)
		if err != nil {
			if delegatedErr := accounts.ParseErrAsDelegatedInternalErr(err); delegatedErr != nil {
				var delegatedParsedErr *accounts.DelegatedRelyingPartyErr
				if errors.As(delegatedErr, &delegatedParsedErr) {
					log.Error(errors.Wrapf(err, "failed to process secure payment confirmation %#v", body))
					ginCtx.JSON(delegatedParsedErr.HTTPStatus, &delegatedParsedErr)
					return
				}
			}
			log.Error(errors.Wrapf(err, "failed to process secure payment confirmation %#v", body))
			ginCtx.JSON(http.StatusInternalServerError, &delegatedErrorResponse{Error: errMessage{Message: "oops, error occured!"}})
			return
		}
		ginCtx.HTML(http.StatusOK, "secure_payment.html", data)
	}
}

func (s *service) AppleAppSiteAssociation(
	ctx context.Context,
	req *server.Request[AppAssociationReq, string],
) (successResp *server.Response[string], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if s.cfg.AppleAppSiteAssociation == "" {
		return nil, server.NotFound(errors.New("not found"), "NOT_FOUND")
	}

	return server.Raw("application/json", []byte(s.cfg.AppleAppSiteAssociation)), nil
}
func (s *service) AssetLinks(
	ctx context.Context,
	req *server.Request[AppAssociationReq, string],
) (successResp *server.Response[string], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if s.cfg.AssetLinks == "" {
		return nil, server.NotFound(errors.New("not found"), "NOT_FOUND")
	}

	return server.Raw("application/json", []byte(s.cfg.AssetLinks)), nil
}

// StartDelegatedRecovery godoc
//
//	@Schemes
//	@Description	Initiates recovery process with delegated RP
//	@Tags			Recovery
//	@Produce		json
//	@Param			request		body		StartDelegatedRecoveryReq	true	"Request params"
//	@Param			X-Client-ID	header		string						true	"App ID"	default(ap-)
//	@Success		200			{object}	StartDelegatedRecoveryResp
//	@Failure		400			{object}	server.ErrorResponse	"if invalid 2FA code is provided"
//	@Failure		403			{object}	server.ErrorResponse	"if 2FA required"
//	@Failure		500			{object}	server.ErrorResponse
//	@Failure		504			{object}	server.ErrorResponse	"if request times out"
//	@Router			/auth/recover/user/delegated [POST].
func (s *service) StartDelegatedRecovery(
	ctx context.Context,
	req *server.Request[StartDelegatedRecoveryReq, StartDelegatedRecoveryResp],
) (successResp *server.Response[StartDelegatedRecoveryResp], errorResp *server.ErrResponse[*delegatedErrorResponse]) {
	if err := req.Data.validate(); err != nil {
		return nil, buildDelegatedErrorResponse(http.StatusBadRequest, errors.Wrapf(err, "invalid 2fa option provided"), invalidPropertiesErrorCode)
	}
	resp, err := s.accounts.StartDelegatedRecovery(withAppID(ctx, req.Data.ClientID), req.Data.Username, req.Data.CredentialID, req.Data.TwoFAVerificationCodes)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNoPending2FA):
			return nil, buildDelegatedErrorResponse(http.StatusBadRequest, err, twoFANoPendingCode)
		case errors.Is(err, accounts.ErrInvalidIdentityKey):
			return nil, buildDelegatedErrorResponse(http.StatusBadRequest, err, invalidUsername)
		case errors.Is(err, accounts.Err2FAExpired):
			return nil, buildDelegatedErrorResponse(http.StatusBadRequest, err, twoFAExpiredCode)
		case errors.Is(err, accounts.Err2FAInvalidCode):
			return nil, buildDelegatedErrorResponse(http.StatusBadRequest, err, twoFAInvalidCode)
		case errors.Is(err, accounts.ErrNotFound):
			return nil, buildDelegatedErrorResponse(http.StatusNotFound, err, userNotFound)
		case errors.Is(err, accounts.Err2FARequired):
			if tErr := terror.As(err); tErr != nil {
				return nil, buildDelegatedErrorResponse(http.StatusForbidden, err, twoFARequired, tErr.Data)
			}
		default:
			if delegatedErr := accounts.ParseErrAsDelegatedInternalErr(err); delegatedErr != nil {
				var delegatedParsedErr *accounts.DelegatedRelyingPartyErr
				if errors.As(delegatedErr, &delegatedParsedErr) {
					return nil, buildDelegatedErrorResponse(delegatedParsedErr.HTTPStatus, err, delegatedParsedErr.Message)
				}
			}
			return nil, buildDelegatedErrorResponse(http.StatusInternalServerError, err, "")
		}
	}
	return server.OK[StartDelegatedRecoveryResp](resp), nil
}

// GetLoginChallenge godoc
//
//	@Schemes
//	@Description	Initiates  login flow
//	@Tags			Login
//	@Produce		json
//	@Param			request		body		GetLoginChallenge	true	"Request params"
//	@Param			X-Client-ID	header		string				true	"App ID"	default(ap-)
//	@Success		200			{object}	LoginChallenge
//	@Failure		400			{object}	server.ErrorResponse	"if invalid 2FA code is provided"
//	@Failure		403			{object}	server.ErrorResponse	"if 2FA required"
//	@Failure		500			{object}	server.ErrorResponse
//	@Failure		504			{object}	server.ErrorResponse	"if request times out"
//	@Router			/auth/login/init [POST].
func (s *service) GetLoginChallenge(
	ctx context.Context,
	req *server.Request[GetLoginChallenge, LoginChallenge],
) (successResp *server.Response[LoginChallenge], errorResp *server.ErrResponse[*delegatedErrorResponse]) {
	if err := req.Data.validate(); err != nil {
		return nil, buildDelegatedErrorResponse(http.StatusBadRequest, errors.Wrapf(err, "invalid 2fa option provided"), invalidPropertiesErrorCode)
	}
	resp, err := s.accounts.GetLoginChallenge(withAppID(ctx, req.Data.ClientID), req.Data.Username, req.Data.TwoFAVerificationCodes)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNoPending2FA):
			return nil, buildDelegatedErrorResponse(http.StatusBadRequest, err, twoFANoPendingCode)
		case errors.Is(err, accounts.ErrInvalidIdentityKey):
			return nil, buildDelegatedErrorResponse(http.StatusBadRequest, err, invalidUsername)
		case errors.Is(err, accounts.Err2FAExpired):
			return nil, buildDelegatedErrorResponse(http.StatusBadRequest, err, twoFAExpiredCode)
		case errors.Is(err, accounts.Err2FAInvalidCode):
			return nil, buildDelegatedErrorResponse(http.StatusBadRequest, err, twoFAInvalidCode)
		case errors.Is(err, accounts.ErrNotFound):
			return nil, buildDelegatedErrorResponse(http.StatusNotFound, err, userNotFound)
		case errors.Is(err, accounts.Err2FARequired):
			if tErr := terror.As(err); tErr != nil {
				return nil, buildDelegatedErrorResponse(http.StatusForbidden, err, twoFARequired, tErr.Data)
			}
		default:
			if delegatedErr := accounts.ParseErrAsDelegatedInternalErr(err); delegatedErr != nil {
				var delegatedParsedErr *accounts.DelegatedRelyingPartyErr
				if errors.As(delegatedErr, &delegatedParsedErr) {
					return nil, buildDelegatedErrorResponse(delegatedParsedErr.HTTPStatus, err, delegatedParsedErr.Message)
				}
			}
			return nil, buildDelegatedErrorResponse(http.StatusInternalServerError, err, "")
		}
	}
	return server.OK[LoginChallenge](resp), nil
}

// CompleteRegistration godoc
//
//	@Schemes
//	@Description	Completes user registration
//	@Tags			Register
//	@Produce		json
//	@Param			request								body		CompletedRegistrationChallenge	true	"Request params"
//	@Param			X-Client-ID							header		string							true	"App ID"	default(ap-)
//	@Param			X-Device-Identification-Request-ID	header		string							true	"Request ID"
//	@Param			Authorization						header		string							true	"Authorization"	default(Bearer <token>)
//	@Success		200									{object}	CompletedRegistration
//	@Failure		400									{object}	server.ErrorResponse	"if challenge is invalid"
//	@Failure		403									{object}	server.ErrorResponse	"if early access email is restructed or auth header invalid"
//	@Failure		500									{object}	server.ErrorResponse
//	@Failure		504									{object}	server.ErrorResponse	"if request times out"
//	@Router			/auth/registration/enduser [POST].
func (s *service) CompleteRegistration(
	ctx context.Context,
	req *server.Request[CompletedRegistrationChallenge, CompletedRegistration],
) (successResp *server.Response[CompletedRegistration], errorResp *server.ErrResponse[*delegatedErrorResponse]) {
	ctx = withAppID(ctx, req.Data.ClientID)
	ctx = withAuth(ctx, req.Data.Authorization)
	ctx = withDeviceIdentificationRequestID(ctx, req.Data.DeviceIdentificationRequestID)
	resp, err := s.accounts.CompleteRegistration(ctx, req.Data.Credentials)
	if err != nil {
		if delegatedErr := accounts.ParseErrAsDelegatedInternalErr(err); delegatedErr != nil {
			var delegatedParsedErr *accounts.DelegatedRelyingPartyErr
			if errors.As(delegatedErr, &delegatedParsedErr) {
				return nil, buildDelegatedErrorResponse(delegatedParsedErr.HTTPStatus, err, delegatedParsedErr.Message)
			}
		}
		return nil, buildDelegatedErrorResponse(http.StatusInternalServerError, err, "")
	}
	return server.OK[CompletedRegistration](&resp), nil
}

// InitRegistration godoc
//
//	@Schemes
//	@Description	Initiates user registration
//	@Tags			Register
//	@Produce		json
//	@Param			request		body		GetLoginChallenge	true	"Request params"
//	@Param			X-Client-ID	header		string				true	"App ID"	default(ap-)
//	@Success		200			{object}	RegistrationChallenge
//	@Failure		403			{object}	server.ErrorResponse	"if early access email is restricted"
//	@Failure		500			{object}	server.ErrorResponse
//	@Failure		504			{object}	server.ErrorResponse	"if request times out"
//	@Router			/auth/registration/delegated [POST].
func (s *service) InitRegistration(
	ctx context.Context,
	req *server.Request[InitRegistration, RegistrationChallenge],
) (successResp *server.Response[RegistrationChallenge], errorResp *server.ErrResponse[*delegatedErrorResponse]) {
	ctx = withAppID(ctx, req.Data.ClientID)
	resp, err := s.accounts.InitRegistration(ctx, req.Data.IdentityKeyName, req.Data.EarlyAccessEmail)
	if err != nil {
		if delegatedErr := accounts.ParseErrAsDelegatedInternalErr(err); delegatedErr != nil {
			var delegatedParsedErr *accounts.DelegatedRelyingPartyErr
			if errors.As(delegatedErr, &delegatedParsedErr) {
				return nil, buildDelegatedErrorResponse(delegatedParsedErr.HTTPStatus, err, delegatedParsedErr.Message)
			}
		}
		return nil, buildDelegatedErrorResponse(http.StatusInternalServerError, err, "")
	}
	return server.OK[RegistrationChallenge](resp), nil
}

// CreateWallet godoc
//
//	@Schemes
//	@Description	Creates wallet on 3rd-party
//	@Tags			Wallets
//	@Produce		json
//	@Param			Authorization	header		string			true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Param			X-Useraction	header		string			true	"User action token"							default(<Add token here>)
//	@Param			X-Client-ID		header		string			true	"App ID"									default(ap-)
//	@Param			request			body		CreateWalletReq	true	"Request params"
//	@Success		200				{object}	Wallet
//	@Failure		409				{object}	delegatedErrorResponse	"if wallet already linked with walletview"
//	@Failure		500				{object}	delegatedErrorResponse
//	@Failure		504				{object}	delegatedErrorResponse	"if request times out"
//	@Router			/wallets [POST].
func (s *service) CreateWallet(
	ctx context.Context,
	req *server.Request[CreateWalletReq, Wallet],
) (successResp *server.Response[Wallet], errorResp *server.ErrResponse[*delegatedErrorResponse]) {
	ctx = withAppID(ctx, req.Data.ClientID)
	ctx = withAuth(ctx, req.Data.Authorization)
	ctx = withUserAction(ctx, req.Data.UserAction)
	wallet, err := s.accounts.CreateWalletForWalletView(ctx, req.AuthenticatedUser.UserID(), req.Data.Network, req.Data.WalletViewID)
	if err != nil {
		if delegatedErr := accounts.ParseErrAsDelegatedInternalErr(err); delegatedErr != nil {
			var delegatedParsedErr *accounts.DelegatedRelyingPartyErr
			if errors.As(delegatedErr, &delegatedParsedErr) {
				return nil, buildDelegatedErrorResponse(delegatedParsedErr.HTTPStatus, err, delegatedParsedErr.Message)
			}
		}
		if errors.Is(err, accounts.ErrWalletLinked) {
			return nil, buildDelegatedErrorResponse(http.StatusConflict, err, duplicate)
		}
		return nil, buildDelegatedErrorResponse(http.StatusInternalServerError, err, "")
	}
	return server.OK[Wallet](wallet), nil
}

func withAppID(ctx context.Context, appID string) context.Context {
	return context.WithValue(ctx, accounts.AppIDHeaderCtxValue, appID)
}
func withUserAction(ctx context.Context, userAction string) context.Context {
	return context.WithValue(ctx, accounts.UserActionCtxValue, userAction)
}
func withAuth(ctx context.Context, auth string) context.Context {
	return context.WithValue(ctx, accounts.AuthorizationHeaderCtxValue, auth)
}
func withDeviceIdentificationRequestID(ctx context.Context, requestId string) context.Context {
	return context.WithValue(ctx, accounts.RequestIDCtxValueKey, requestId)
}

func (r *StartDelegatedRecoveryReq) validate() error {
	for reqOpt := range r.TwoFAVerificationCodes {
		if err := reqOpt.Validate(); err != nil {
			return err
		}
	}
	return nil
}
func (r *GetLoginChallenge) validate() error {
	for reqOpt := range r.TwoFAVerificationCodes {
		if err := reqOpt.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (s *service) EventWebhookFromDelegatedRP(
	ctx context.Context,
	req *server.Request[WebhookData, WebhookResp],
) (successResp *server.Response[WebhookResp], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	log.Info(fmt.Sprintf("Webhook call for %v %+v", req.Data.Kind, req.Data.Data))
	return server.OK[WebhookResp](&WebhookResp{}), nil
}
