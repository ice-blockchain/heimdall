// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) Verify2FA(ctx context.Context, userID string, userInputCodes map[TwoFAOptionEnum]string) error {
	codes, err := a.get2FACodes(ctx, userID, userInputCodes)
	if err != nil {
		return errors.Wrapf(err, "failed to verify codes %v for userID %v", userInputCodes, userID)
	}
	now := time.Now()
	var vErr error
	for t, c := range codes {
		if vErr = c.expired(a, now); vErr != nil {
			break
		}
		if vErr = c.invalidCode(a, now, userInputCodes[t]); vErr != nil {
			break
		}
	}
	if vErr != nil {
		return errors.Wrapf(vErr, "failed to verify 2FA code")
	}
	return errors.Wrapf(a.updateUserWithConfirmed2FA(ctx, now, userID, codes), "failed to update users")
}

func (c *twoFACode) expired(a *accounts, now *time.Time) error {
	expired := false
	switch c.Option {
	case TwoFAOptionEmail:
		expired = now.After(c.CreatedAt.Add(a.cfg.EmailExpiration))
	case TwoFAOptionSMS:
		expired = now.After(c.CreatedAt.Add(a.cfg.SMSExpiration))
	}
	if expired {
		return Err2FAExpired
	}
	return nil
}
func (c *twoFACode) invalidCode(a *accounts, now *time.Time, inputCode string) error {
	invalidCode := false
	switch c.Option {
	case TwoFAOptionEmail, TwoFAOptionSMS:
		invalidCode = c.Code != inputCode
	case TwoFAOptionTOTPAuthentificator:
		invalidCode = !(a.totpProvider.Verify(now, c.Code, inputCode))
	}
	if invalidCode {
		return Err2FAInvalidCode
	}

	return nil
}

func (a *accounts) updateUserWithConfirmed2FA(ctx context.Context, now *time.Time, userID string, codes map[TwoFAOptionEnum]*twoFACode) error {
	if len(codes) == 0 {
		return nil
	}
	whereClause, extraParams := buildWhereClause(codes)
	authentificatorCode := ""
	if authentificator, hasAuthentificator := codes[TwoFAOptionTOTPAuthentificator]; hasAuthentificator {
		authentificatorCode = authentificator.Code
	}
	params := append([]any{userID, *now.Time, authentificatorCode}, extraParams...)
	sql := fmt.Sprintf(`
WITH upd AS (
    UPDATE twofa_codes SET
        confirmed_at = $2,
        code = user_id
        WHERE user_id = $1 AND (%v)
        RETURNING
            user_id as user_id,
            option,
            (CASE WHEN option = 'email' THEN deliver_to ELSE NULL END) as email,
            (CASE WHEN option = 'sms' THEN deliver_to ELSE NULL END) as phone_number,
            (CASE WHEN option = 'google_authentificator' THEN $3 ELSE NULL END) as totp_authentificator_secret
), collapsed AS (
    select $1 as id,
           (array_agg(email) FILTER ( WHERE email is not null))[1] as email,
           (array_agg(phone_number) FILTER ( WHERE phone_number is not null))[1] as phone_number,
           (array_agg(totp_authentificator_secret) FILTER ( WHERE totp_authentificator_secret is not null))[1] as totp_authentificator_secret
    from upd
), upd_users AS (
	UPDATE users SET
		   email = COALESCE(NULLIF(collapsed.email,users.email), users.email),
		   phone_number = COALESCE(NULLIF(collapsed.phone_number,users.phone_number), users.phone_number),
		   totp_authentificator_secret = COALESCE(NULLIF(collapsed.totp_authentificator_secret,users.totp_authentificator_secret), users.totp_authentificator_secret)
	FROM collapsed, upd
	WHERE users.id = $1
	returning users.id
)
SELECT upd.option as option from upd
inner join upd_users on upd.user_id = upd_users.id;`, whereClause)
	res, err := storage.ExecMany[struct {
		Option TwoFAOptionEnum `db:"option"`
	}](ctx, a.db, sql, params...)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return errors.Wrapf(err, "failed to update user with 2FA passed")
	}
	if len(res) != len(codes) {
		missing := make([]TwoFAOptionEnum, 0, len(codes)-len(res))
		for c := range codes {
			f := false
			for _, r := range res {
				if c == r.Option {
					f = true
					break
				}
			}
			if !f {
				missing = append(missing, c)
			}
		}
		if !(len(missing) == 1 && missing[0] == TwoFAOptionTOTPAuthentificator) {
			return Err2FAInvalidCode
		}
	}
	return nil
}

func buildWhereClause(codes map[TwoFAOptionEnum]*twoFACode) (string, []any) {
	where := make([]string, 0, len(codes))
	params := make([]any, 0, len(codes)*2)
	nextIndex := 4
	for _, c := range codes {
		where = append(where, fmt.Sprintf("(option = $%[1]v and code =$%[2]v )", nextIndex, nextIndex+1))
		params = append(params, c.Option, c.Code)
		nextIndex += 2
	}
	return strings.Join(where, " OR "), params
}

func (a *accounts) get2FACodes(ctx context.Context, userID string, inputCodes map[TwoFAOptionEnum]string) (map[TwoFAOptionEnum]*twoFACode, error) {
	kinds := make([]string, 0, len(inputCodes))
	for k := range inputCodes {
		kinds = append(kinds, k)
	}
	sql := fmt.Sprintf(`SELECT 
    	created_at,
    	user_id,
    	option,
    	deliver_to,
    	(case WHEN option = '%[1]v' THEN COALESCE(u.totp_authentificator_secret, twofa_codes.code) ELSE twofa_codes.code END) as code,
    	confirmed_at
    FROM twofa_codes 
    INNER JOIN users u on u.id = twofa_codes.user_id
    WHERE twofa_codes.user_id = $1 and option = ANY($2)`, TwoFAOptionTOTPAuthentificator)
	codes, err := storage.Select[twoFACode](ctx, a.db, sql, userID, kinds)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to select 2fa codes")
	}
	if len(codes) != len(inputCodes) {
		return nil, ErrNoPending2FA
	}
	res := make(map[TwoFAOptionEnum]*twoFACode)
	for _, c := range codes {
		res[c.Option] = c
	}

	return res, nil
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
	length := 6

	result, err := rand.Int(rand.Reader, big.NewInt(int64(math.Pow10(length)-1))) //nolint:gomnd // It's max value.
	log.Panic(err, "random wrong")

	str := fmt.Sprintf("%03d", result.Int64()+1)
	if missingNums := length - len(str); missingNums > 0 {
		str = strings.Repeat("0", missingNums) + str
	}
	return str
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
		if newChannel != nil && existingDeliveryChannel != "" && existingDeliveryChannel != *newChannel {
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
