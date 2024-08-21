// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/server"
)

func (s *service) setup2FARoutes(router gin.IRoutes) {
	router.
		POST("v1/users/:userId/2fa/:twoFAOption/verification-requests", server.RootHandler(s.Send2FARequest)).
		PUT("v1/users/:userId/2fa/:twoFAOption/verification-requests", server.RootHandler(s.Verify2FARequest))
}

// Send2FARequest godoc
//
//	@Schemes
//	@Description	Initiates sending of 2FA code to the user
//	@Tags			2FA
//	@Produce		json
//	@Param			X-Language		header		string				false	"Language"		default(en)
//	@Param			Authorization	header		string				true	"Auth header"	default(Bearer <token>)
//	@Param			userId			path		string				true	"ID of the user"
//	@Param			twoFAOption		path		string				true	"type of 2fa (sms/email/google_authentificator)"
//	@Param			request			body		Send2FARequestReq	true	"Request params containing email or phone number to set up 2FA"
//	@Success		200				{object}	Send2FARequestResp
//	@Failure		400				{object}	server.ErrorResponse	"if user's email / phone number is not provided"
//	@Failure		403				{object}	server.ErrorResponse	"if user already have 2FA set up, and it is requested for new email / phone"
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/2fa/{twoFAOption}/verification-requests [POST].
func (s *service) Send2FARequest(
	ctx context.Context,
	req *server.Request[Send2FARequestReq, Send2FARequestResp],
) (successResp *server.Response[Send2FARequestResp], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if req.Data.Language == "" {
		req.Data.Language = "en"
	}
	channel, err := req.Data.deliveryChannel()
	if err != nil {
		return nil, server.UnprocessableEntity(err, invalidPropertiesErrorCode)
	}
	var authentificatorUri *string
	authentificatorUri, err = s.accounts.Send2FA(ctx, req.Data.UserID, req.Data.TwoFAOption, channel, req.Data.Language)
	if err != nil {
		switch {
		case errors.Is(err, accounts.Err2FAAlreadySetup):
			return nil, server.ForbiddenWithCode(err, twoFAAlreadySetupErrorCode)
		case errors.Is(err, accounts.Err2FADeliverToNotProvided):
			return nil, server.BadRequest(err, invalidPropertiesErrorCode)
		default:
			return nil, server.Unexpected(err)
		}
	}
	return server.OK[Send2FARequestResp](&Send2FARequestResp{TOTPAuthentificatorURL: authentificatorUri}), nil
}

func (s *Send2FARequestReq) deliveryChannel() (*string, error) {
	switch s.TwoFAOption {
	case accounts.TwoFAOptionEmail:
		return s.Email, nil
	case accounts.TwoFAOptionSMS:
		return s.PhoneNumber, nil
	case accounts.TwoFAOptionTOTPAuthentificator:
		return nil, nil
	default:
		return nil, errors.Errorf("invalid 2faOption: %v", s.TwoFAOption)
	}
}

// Verify2FARequest godoc
//
//	@Schemes
//	@Description	Verifies 2FA code from the user
//	@Tags			2FA
//	@Produce		json
//	@Param			userId			path		string	true	"ID of the user"
//	@Param			twoFAOption		path		string	true	"type of 2fa (sms/email/google_authentificator)"
//	@Param			code			query		string	true	"code from second factor"
//	@Param			Authorization	header		string	true	"Auth header"	default(Bearer <token>)
//	@Success		200				{object}	Verify2FARequestResp
//	@Failure		400				{object}	server.ErrorResponse	"if code is invalid or expired"
//	@Failure		409				{object}	server.ErrorResponse	"if there is no pending 2FA verification"
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/2fa/{twoFAOption}/verification-requests [PUT].
func (s *service) Verify2FARequest(
	ctx context.Context,
	req *server.Request[Verify2FARequestReq, Verify2FARequestResp],
) (successResp *server.Response[Verify2FARequestResp], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if err := req.Data.validate(); err != nil {
		return nil, server.UnprocessableEntity(err, invalidPropertiesErrorCode)
	}
	if err := s.accounts.Verify2FA(ctx, req.Data.UserID, map[accounts.TwoFAOptionEnum]string{
		req.Data.TwoFAOption: req.Data.Code,
	}); err != nil {
		switch {
		case errors.Is(err, accounts.ErrNoPending2FA):
			return nil, server.Conflict(err, twoFANoPendingCode)
		case errors.Is(err, accounts.Err2FAExpired):
			return nil, server.BadRequest(err, twoFAExpiredCode)
		case errors.Is(err, accounts.Err2FAInvalidCode):
			return nil, server.BadRequest(err, twoFAInvalidCode)
		default:
			return nil, server.Unexpected(err)
		}
	}
	return server.OK[Verify2FARequestResp](&Verify2FARequestResp{}), nil
}

func (r *Verify2FARequestReq) validate() error {
	for _, opt := range accounts.AllTwoFAOptions {
		if r.TwoFAOption == opt {
			return nil
		}
	}
	return errors.Errorf("invalid 2fa option: %v", r.TwoFAOption)
}
