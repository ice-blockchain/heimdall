// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) Verify2FA(ctx context.Context, userID string, codes map[TwoFAOptionEnum]string) error {
	return errors.New("not impl")
}
func (a *accounts) Send2FA(ctx context.Context, userID string, opt TwoFAOptionEnum, optDeliverTo *string, language string) (*string, error) {
	deliverTo, err := a.checkDeliveryChannelFor2FA(ctx, userID, opt, optDeliverTo)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to detect where to deviver 2fa")
	}
	var code string
	if opt == TwoFAOptionTOTPAuthentificator {
		code = generateAuthentifcatorSecret()
	} else {
		code = generateConfirmationCode()
	}
	if uErr := a.upsert2FACode(ctx, &twoFACode{
		CreatedAt: time.Now(),
		UserID:    userID,
		Option:    opt,
		DeliverTo: deliverTo,
		Code:      code,
	}); uErr != nil {
		return nil, errors.Wrapf(uErr, "failed to upsert code for userID %v", userID)
	}
	authentificatorUri, dErr := a.deliverCode(ctx, opt, deliverTo, code, language)
	if dErr != nil {
		return nil, errors.Wrapf(dErr, "failed to deliver 2fa code to user %v with %v:%v", userID, opt, deliverTo)
	}
	return authentificatorUri, nil
}

func generateConfirmationCode() string {
	result, err := rand.Int(rand.Reader, big.NewInt(999999)) //nolint:gomnd // It's max value.
	log.Panic(err, "random wrong")

	return fmt.Sprintf("%03d", result.Int64()+1)
}
func generateAuthentifcatorSecret() string {
	const length = 10
	secret := make([]byte, length)
	gen, err := rand.Read(secret)
	if err != nil || gen != length {
		if gen != length {
			err = errors.Errorf("unexpected length: %v instead of %v", gen, length)
		}
		log.Panic(err, "random wrong")
	}
	return base64.StdEncoding.EncodeToString(secret)
}

func (a *accounts) deliverCode(ctx context.Context, opt TwoFAOptionEnum, deliverTo, code string, language string) (*string, error) {
	var codeDeliverer interface {
		DeliverCode(ctx context.Context, code, emailAddress, language string) error
	}
	switch opt {
	case TwoFAOptionTOTPAuthentificator:
		uri := a.totpProvider.GenerateURI(code, deliverTo)
		return &uri, nil
	case TwoFAOptionEmail:
		codeDeliverer = a.emailCode
	default:
		return nil, errors.Errorf("Check what sms provider will be used wintr/sms(twilio) or smth else")
	}
	if codeDeliverer != nil {
		return nil, codeDeliverer.DeliverCode(ctx, code, deliverTo, language)
	}
	return nil, errors.Errorf("Check what sms provider will be used wintr/sms(twilio) or smth else")
}

func (a *accounts) checkDeliveryChannelFor2FA(ctx context.Context, userID string, opt TwoFAOptionEnum, newChannel *string) (string, error) {
	var existingDeliveryChannel string
	usr, err := a.getUserByID(ctx, userID)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return "", errors.Wrapf(err, "failed to check existing user phone and email for userID %v", userID)
	}
	if usr != nil {
		switch {
		case opt == TwoFAOptionEmail && usr.Email != nil:
			existingDeliveryChannel = *usr.Email
		case opt == TwoFAOptionSMS && usr.PhoneNumber != nil:
			existingDeliveryChannel = *usr.PhoneNumber
		case opt == TwoFAOptionTOTPAuthentificator && usr.TotpAuthentificatorSecret != nil:
			return "", Err2FAAlreadySetup
		}
		if existingDeliveryChannel != "" && existingDeliveryChannel != *newChannel {
			return "", Err2FAAlreadySetup
		}
	}
	if existingDeliveryChannel != "" {
		return existingDeliveryChannel, nil
	}
	if opt == TwoFAOptionTOTPAuthentificator {
		var accountName string
		switch {
		case usr.Email != nil:
			accountName = *usr.Email
		case usr.PhoneNumber != nil:
			accountName = *usr.PhoneNumber
		default:
			return "", errors.Errorf("cannot setup authentificator without setting up email / phone before")
		}
		return accountName, nil
	}
	if newChannel == nil {
		return "", Err2FADeliverToNotProvided
	}
	return *newChannel, nil

}

func (a *accounts) upsert2FACode(ctx context.Context, codeInfo *twoFACode) error {
	sql := `INSERT INTO twofa_codes (created_at, user_id, option, deliver_to, code) VALUES ($1, $2, $3, $4, $5) 
			ON CONFLICT (user_id, option) DO UPDATE SET 
                                            created_at = excluded.created_at,
                                            deliver_to = excluded.deliver_to,
                                            code = excluded.code
			WHERE twofa_codes.code != excluded.code OR twofa_codes.deliver_to != excluded.deliver_to;`
	_, err := storage.Exec(ctx, a.db, sql, codeInfo.CreatedAt, codeInfo.UserID, codeInfo.Option, codeInfo.DeliverTo, codeInfo.Code)

	return errors.Wrapf(err, "failed to upsert in-progress 2fa code info for userID %v %#v", codeInfo.UserID, codeInfo)
}
