// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/terror"
)

func (s *service) setup2FARoutes(router gin.IRoutes) {
	router.
		PUT("v1/users/:userId/2fa/:twoFAOption/verification-requests", server.RootHandler(s.Send2FARequest)).
		PATCH("v1/users/:userId/2fa/:twoFAOption/verification-requests", server.RootHandler(s.Verify2FARequest)).
		DELETE("v1/users/:userId/2fa/:twoFAOption/values/:twoFAOptionValue", server.RootHandler(s.Delete2FA))
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
//	@Param			twoFAOption		path		string				true	"type of 2fa (sms/email/totp_authenticator)"
//	@Param			request			body		Send2FARequestReq	true	"Request params containing email or phone number to set up 2FA"
//	@Success		200				{object}	Send2FARequestResp
//	@Failure		400				{object}	server.ErrorResponse	"if user's email / phone number is not provided"
//	@Failure		403				{object}	server.ErrorResponse	"if user already have 2FA set up, and it is requested for new email / phone"
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/2fa/{twoFAOption}/verification-requests [PUT].
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
	var authenticatorUri *string
	authenticatorUri, err = s.accounts.Send2FA(ctx, req.Data.UserID, req.Data.TwoFAOption, channel, req.Data.Language, req.Data.TwoFAVerificationCodes)
	if err != nil {
		switch {
		case errors.Is(err, accounts.Err2FARequired):
			if tErr := terror.As(err); tErr != nil {
				return nil, server.ForbiddenWithCode(err, twoFARequired, tErr.Data)
			}
		case errors.Is(err, accounts.Err2FADeliverToNotProvided):
			return nil, server.BadRequest(err, invalidPropertiesErrorCode)
		case errors.Is(err, accounts.Err2FAExpired):
			return nil, server.BadRequest(err, twoFAExpiredCode)
		case errors.Is(err, accounts.Err2FAInvalidCode):
			return nil, server.BadRequest(err, twoFAInvalidCode)
		case errors.Is(err, accounts.ErrNoPending2FA):
			return nil, server.BadRequest(err, twoFAInvalidCode)
		case errors.Is(err, accounts.ErrAuthenticatorRequirementsNotMet):
			return nil, server.BadRequest(err, authenticatorReqNotMet)
		default:
			return nil, server.Unexpected(err)
		}
	}
	return server.OK[Send2FARequestResp](&Send2FARequestResp{TOTPAuthenticatorURL: authenticatorUri}), nil
}

// Delete2FA godoc
//
//	@Schemes
//	@Description	Confirms deletion of 2FA method
//	@Tags			2FA
//	@Produce		json
//	@Param			Authorization					header	string		true	"Auth header"	default(Bearer <token>)
//	@Param			userId							path	string		true	"ID of the user"
//	@Param			twoFAOption						path	string		true	"type of 2fa (sms/email/totp_authenticator)"
//	@Param			twoFAOptionValue				path	string		true	"the actual value of the twoFAOption"
//	@Param			twoFAOptionVerificationCode		query	[]string	true	"the code received via twoFAOptionVerificationValue"
//	@Param			twoFAOptionVerificationValue	query	[]string	true	"the provider received the codes"
//	@Success		200								"OK - found and deleted"
//	@Success		204								"OK - no such 2FA"
//	@Failure		400								{object}	server.ErrorResponse	"Wrong 2FA codes provided"
//	@Failure		403								{object}	server.ErrorResponse	"No 2FA codes provided to approve removal"
//	@Failure		500								{object}	server.ErrorResponse
//	@Failure		504								{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/2fa/{twoFAOption}/values/{twoFAOptionValue} [DELETE].
func (s *service) Delete2FA(
	ctx context.Context,
	req *server.Request[Delete2FAReq, any],
) (successResp *server.Response[any], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	verificationCodes, err := req.Data.verificationCodes()
	if err != nil {
		return nil, server.UnprocessableEntity(err, invalidPropertiesErrorCode)
	}
	if err = s.accounts.Delete2FA(ctx, req.Data.UserID, verificationCodes, req.Data.TwoFAOption, req.Data.TwoFAOptionValue); err != nil {
		switch {
		case errors.Is(err, accounts.ErrNoPending2FA):
			return server.NoContent(), nil
		case errors.Is(err, accounts.Err2FARequired):
			if tErr := terror.As(err); tErr != nil {
				return nil, server.ForbiddenWithCode(err, twoFARequired, tErr.Data)
			}
		case errors.Is(err, accounts.Err2FADeliverToNotProvided):
			return nil, server.BadRequest(err, invalidPropertiesErrorCode)
		case errors.Is(err, accounts.Err2FAExpired):
			return nil, server.BadRequest(err, twoFAExpiredCode)
		case errors.Is(err, accounts.Err2FAInvalidCode):
			return nil, server.BadRequest(err, twoFAInvalidCode)
		case errors.Is(err, accounts.ErrAuthenticatorRequirementsNotMet):
			return nil, server.BadRequest(err, authenticatorReqNotMet)
		default:
			return nil, server.Unexpected(err)
		}
	}
	return server.OK[any](), nil
}

func (d *Delete2FAReq) verificationCodes() (map[TwoFAOptionEnum]string, error) {
	if len(d.TwoFAOptionVerificationValue) != len(d.TwoFAOptionVerificationCode) {
		return nil, errors.Errorf("mismatched length of twoFAOptionVerificationCode (%v) and twoFAOptionVerificationValue (%v)",
			len(d.TwoFAOptionVerificationCode), len(d.TwoFAOptionVerificationValue))
	}
	res := make(map[TwoFAOptionEnum]string, len(d.TwoFAOptionVerificationValue))
	for i, twoFAProvider := range d.TwoFAOptionVerificationValue {
		res[twoFAProvider] = d.TwoFAOptionVerificationCode[i]
	}
	return res, nil
}

func (s *Send2FARequestReq) deliveryChannel() (*string, error) {
	switch s.TwoFAOption {
	case accounts.TwoFAOptionEmail:
		return s.Email, nil
	case accounts.TwoFAOptionSMS:
		return s.PhoneNumber, nil
	case accounts.TwoFAOptionTOTPAuthenticator:
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
//	@Param			twoFAOption		path		string	true	"type of 2fa (sms/email/totp_authenticator)"
//	@Param			code			query		string	true	"code from second factor"
//	@Param			Authorization	header		string	true	"Auth header"	default(Bearer <token>)
//	@Success		200				{object}	Verify2FARequestResp
//	@Failure		400				{object}	server.ErrorResponse	"if code is invalid or expired"
//	@Failure		409				{object}	server.ErrorResponse	"if there is no pending 2FA verification"
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/2fa/{twoFAOption}/verification-requests [PATCH].
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
