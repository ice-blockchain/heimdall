// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	stdlibtime "time"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/terror"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) Verify2FA(ctx context.Context, userID string, userInputCodes map[TwoFAOptionEnum]string) error {
	_, err := a.verifyAndRedeem2FA(ctx, userID, userInputCodes)
	return errors.Wrapf(err, "failed to update codes as redeemed")
}
func (a *accounts) verifyAndRedeem2FA(ctx context.Context, userID string, userInputCodes map[TwoFAOptionEnum]string) (rollback map[TwoFAOptionEnum]string, err error) {
	now := time.Now()
	var codes map[TwoFAOptionEnum]*twoFACode
	if codes, err = a.verify2FA(ctx, now, userID, userInputCodes); err != nil {
		return nil, errors.Wrapf(err, "falied to verify codes")
	}
	return a.updateUserWithConfirmed2FA(ctx, now, userID, codes)
}

func (a *accounts) verify2FA(ctx context.Context, now *time.Time, userID string, inputCodes map[TwoFAOptionEnum]string) (map[TwoFAOptionEnum]*twoFACode, error) {
	codes, err := a.get2FACodes(ctx, userID, inputCodes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get pending codes %v for userID %v", inputCodes, userID)
	}
	var vErr error
	for t, c := range codes {
		if vErr = c.expired(a, now); vErr != nil {
			break
		}
		if vErr = c.invalidCode(a, now, inputCodes[t]); vErr != nil {
			break
		}
	}
	return codes, errors.Wrapf(vErr, "failed to verify 2FA code")
}

func (a *accounts) rollbackRedeemed2FACodes(usrID string, codes map[TwoFAOptionEnum]string) error {
	rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 5*stdlibtime.Second)
	defer rollbackCancel()
	rollbackCaseClause, rbParams := buildRollbackClause(codes)
	params := append([]any{usrID, maps.Keys(codes)}, rbParams...)
	sql := fmt.Sprintf(`UPDATE twofa_codes SET
        confirmed_at = NULL,
        code = (%v)
        WHERE user_id = $1 AND code = user_id AND option = ANY($2)`, rollbackCaseClause)
	_, err := storage.Exec(rollbackCtx, a.db, sql, params...)
	return errors.Wrapf(err, "failed to rollback codes for userID %v", usrID)
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
	case TwoFAOptionTOTPAuthenticator:
		invalidCode = !(a.totpProvider.Verify(now, c.Code, inputCode))
	}
	if invalidCode {
		return Err2FAInvalidCode
	}

	return nil
}

func (a *accounts) updateUserWithConfirmed2FA(ctx context.Context, now *time.Time, userID string, codes map[TwoFAOptionEnum]*twoFACode) (codesToRollback map[TwoFAOptionEnum]string, err error) {
	addEmailClause := "(case when users.email @> ARRAY[collapsed.email] then users.email else array_prepend(collapsed.email, users.email) end) "
	addPhoneClause := "(case when users.phone_number @> ARRAY[collapsed.phone_number] then users.phone_number else array_prepend(collapsed.phone_number, users.phone_number) end)"
	addTotpClause := "(case when users.totp_authenticator_secret @> ARRAY[collapsed.totp_authenticator_secret] then users.totp_authenticator_secret else array_prepend(collapsed.totp_authenticator_secret, users.totp_authenticator_secret) end)"
	return a.updateUserWithConfirmedOrDeleted2FA(ctx, now, userID, codes, "", addEmailClause, addPhoneClause, addTotpClause)
}

func (a *accounts) updateUserWithDeleted2FA(ctx context.Context, now *time.Time, usr *user, confirmedRemovalByCodes map[TwoFAOptionEnum]*twoFACode, removableOption TwoFAOptionEnum, removable2FAValue string) (codesToRollback map[TwoFAOptionEnum]string, err error) {
	removeEmailClause := "users.email"
	removePhoneClause := "users.phone_number"
	removeTotpClause := "users.totp_authenticator_secret"
	contains := false
	switch removableOption {
	case TwoFAOptionEmail:
		removeEmailClause = "array_remove(users.email, $4)"
		contains = slices.Contains(usr.Email, removable2FAValue)
	case TwoFAOptionSMS:
		removePhoneClause = "array_remove(users.phone_number, $4)"
		contains = slices.Contains(usr.PhoneNumber, removable2FAValue)
	case TwoFAOptionTOTPAuthenticator:
		removeTotpClause = "array_remove(users.totp_authenticator_secret, $4)"
		var idx int
		idx, err = strconv.Atoi(removable2FAValue)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse totpSecret index")
		}
		contains = len(usr.TotpAuthenticatorSecret) >= idx+1
		if !contains {
			return nil, ErrNoPending2FA
		}
		removable2FAValue = usr.TotpAuthenticatorSecret[idx]
	}
	if !contains {
		return nil, ErrNoPending2FA
	}
	return a.updateUserWithConfirmedOrDeleted2FA(ctx, now, usr.ID, confirmedRemovalByCodes, removable2FAValue, removeEmailClause, removePhoneClause, removeTotpClause)
}

func (a *accounts) updateUserWithConfirmedOrDeleted2FA(
	ctx context.Context,
	now *time.Time,
	userID string,
	codes map[TwoFAOptionEnum]*twoFACode,
	removal string,
	addOrRemoveEmailClause, addOrRemovePhoneClause, addOrRemoveTotpClause string,
) (codesToRollback map[TwoFAOptionEnum]string, err error) {
	if len(codes) == 0 {
		return map[TwoFAOptionEnum]string{}, nil
	}
	whereClause, extraParams := buildWhereClause(codes)
	authenticatorCode := ""
	if authenticator, hasauthenticator := codes[TwoFAOptionTOTPAuthenticator]; hasauthenticator {
		authenticatorCode = authenticator.Code
	}
	params := append([]any{userID, *now.Time, authenticatorCode, removal}, extraParams...)
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
            (CASE WHEN option = '%[2]v' THEN $3 ELSE NULL END) as totp_authenticator_secret
), collapsed AS (
    select $1 as id,
           (array_agg(email) FILTER ( WHERE email is not null))[1] as email,
           (array_agg(phone_number) FILTER ( WHERE phone_number is not null))[1] as phone_number,
           (array_agg(totp_authenticator_secret) FILTER ( WHERE totp_authenticator_secret is not null))[1] as totp_authenticator_secret
    from upd
), upd_users AS (
	UPDATE users SET
           updated_at = $2,
		   email = array_remove(%[3]v, NULL),
		   phone_number = array_remove(%[4]v, NULL),
		   totp_authenticator_secret = array_remove(%[5]v, NULL),
           active_2fa_email = (CASE WHEN users.email = ARRAY[$4] THEN NULL WHEN (users.active_2fa_email + 1) = cardinality(users.email) AND users.email @> ARRAY[$4] THEN GREATEST(users.active_2fa_email-1,0)  WHEN (NOT (users.email @> ARRAY[collapsed.email]) and collapsed.email is not null) THEN 0 ELSE users.active_2fa_email END),
           active_2fa_phone_number = (CASE WHEN users.phone_number = ARRAY[$4] THEN NULL WHEN (users.active_2fa_phone_number + 1) = cardinality(users.phone_number) AND users.phone_number @> ARRAY[$4] THEN GREATEST(users.active_2fa_phone_number-1,0)  WHEN (NOT(users.phone_number @> ARRAY[collapsed.phone_number]) and collapsed.phone_number is not null) THEN 0 ELSE users.active_2fa_phone_number END),
           active_2fa_totp_authenticator = (CASE WHEN users.totp_authenticator_secret = ARRAY[$4] THEN NULL WHEN (users.active_2fa_totp_authenticator + 1) = cardinality(users.totp_authenticator_secret) AND users.totp_authenticator_secret @> ARRAY[$4] THEN GREATEST(users.active_2fa_totp_authenticator-1,0)  WHEN NULLIF (collapsed.totp_authenticator_secret,users.id) IS NOT NULL THEN 0 ELSE users.active_2fa_totp_authenticator END)
	FROM collapsed
	WHERE users.id = $1
	returning users.id
)
SELECT upd.option as option from upd
inner join upd_users on upd.user_id = upd_users.id;`, whereClause, TwoFAOptionTOTPAuthenticator, addOrRemoveEmailClause, addOrRemovePhoneClause, addOrRemoveTotpClause)
	res, err := storage.ExecMany[struct {
		Option TwoFAOptionEnum `db:"option"`
	}](ctx, a.db, sql, params...)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to update user with 2FA passed")
	}
	codesForRollback := make(map[TwoFAOptionEnum]string, len(codes))
	if len(res) != len(codes) {
		missing := make([]TwoFAOptionEnum, 0, len(codes)-len(res))
		for c := range codes {
			f := false
			for _, r := range res {
				codesForRollback[r.Option] = codes[r.Option].Code
				if c == r.Option {
					f = true
				}
			}
			if !f {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 && !(len(missing) == 1 && missing[0] == TwoFAOptionTOTPAuthenticator) {
			log.Error(a.rollbackRedeemed2FACodes(userID, codesForRollback))
			return nil, Err2FAInvalidCode
		}
	}
	return codesForRollback, nil
}

func buildWhereClause(codes map[TwoFAOptionEnum]*twoFACode) (string, []any) {
	where := make([]string, 0, len(codes))
	params := make([]any, 0, len(codes)*2)
	nextIndex := 5
	for _, c := range codes {
		where = append(where, fmt.Sprintf("(option = $%[1]v and code = $%[2]v )", nextIndex, nextIndex+1))
		params = append(params, c.Option, c.Code)
		nextIndex += 2
	}
	return strings.Join(where, " OR "), params
}
func buildRollbackClause(codes map[TwoFAOptionEnum]string) (string, []any) {
	cases := make([]string, 0, len(codes))
	params := make([]any, 0, len(codes)*2)
	nextIndex := 3
	for k, v := range codes {
		cases = append(cases, fmt.Sprintf("WHEN option = $%[1]v THEN $%[2]v", nextIndex, nextIndex+1))
		params = append(params, k, v)
		nextIndex += 2
	}
	return "CASE \n" + strings.Join(cases, "\n") + "\nEND", params
}

func (a *accounts) get2FACodes(ctx context.Context, userID string, inputCodes map[TwoFAOptionEnum]string) (map[TwoFAOptionEnum]*twoFACode, error) {
	kinds := make([]string, 0, len(inputCodes))
	for k := range inputCodes {
		kinds = append(kinds, k)
	}
	sql := fmt.Sprintf(`SELECT 
    	twofa_codes.created_at as created_at,
    	user_id,
    	option,
    	deliver_to,
    	(case WHEN option = '%[1]v' THEN COALESCE(NULLIF(twofa_codes.code,u.id), u.totp_authenticator_secret[(u.active_2fa_totp_authenticator + 1)]) ELSE twofa_codes.code END) as code,
    	confirmed_at
    FROM twofa_codes 
    INNER JOIN users u on u.id = twofa_codes.user_id
    WHERE twofa_codes.user_id = $1 and option = ANY($2)`, TwoFAOptionTOTPAuthenticator)
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

func (a *accounts) Send2FA(ctx context.Context, userID string, opt TwoFAOptionEnum, optDeliverTo *string, language string, existing2FAVerificationForModify map[TwoFAOptionEnum]string) (*string, error) {
	var codesForRollback map[TwoFAOptionEnum]string
	usr, err := a.getUserByID(ctx, userID)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to check existing user phone and email for userID %v", userID)
	}
	deliverTo, err := a.checkDeliveryChannelFor2FA(ctx, usr, opt, optDeliverTo)
	if err != nil {
		if !errors.Is(err, Err2FARequired) {
			return nil, errors.Wrapf(err, "failed to detect where to deviver 2fa")
		}
		if err = checkIfAll2FAProvided(usr, existing2FAVerificationForModify); err != nil {
			return nil, err //nolint:wrapcheck // tErr.
		}
		codesForRollback, err = a.verifyAndRedeem2FA(ctx, userID, existing2FAVerificationForModify)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to verify existing 2fa for user %v", userID)
		}
	}
	var code string
	if opt == TwoFAOptionTOTPAuthenticator {
		code = a.generateAuthentifcatorSecret(opt, userID)
	} else {
		code = a.generateConfirmationCode(opt, userID)
	}
	defer a.concurrentlyGeneratedCodes[opt].Delete(userID)
	if uErr := a.upsert2FACode(ctx, &twoFACode{
		CreatedAt: time.Now(),
		UserID:    userID,
		Option:    opt,
		DeliverTo: deliverTo,
		Code:      code,
	}); uErr != nil {
		return nil, multierror.Append(
			errors.Wrapf(uErr, "failed to upsert code for userID %v", userID),
			errors.Wrapf(a.rollbackRedeemed2FACodes(userID, codesForRollback), "[rollback] failed to rollback 2fa codes to approve modification for user %v", userID),
		).ErrorOrNil()

	}

	authenticatorUri, dErr := a.deliverCode(ctx, opt, code, language, deliverTo) // TODO: selection of active 2fa in
	if dErr != nil {
		return nil, multierror.Append(
			errors.Wrapf(dErr, "failed to deliver 2fa code to user %v with %v:%v", userID, opt, deliverTo),
			errors.Wrapf(a.rollbackRedeemed2FACodes(userID, codesForRollback), "[rollback] failed to rollback 2fa codes to approve modification for user %v", userID),
		).ErrorOrNil()
	}
	return authenticatorUri, nil
}

func (a *accounts) generateConfirmationCode(opt TwoFAOptionEnum, userID string) string {
	if alreadyGeneratedCode, alreadyGenerated := a.concurrentlyGeneratedCodes[opt].Load(userID); alreadyGenerated {
		return alreadyGeneratedCode.(string)
	}
	result, err := rand.Int(rand.Reader, big.NewInt(int64(math.Pow10(confirmationCodeLength)-1))) //nolint:gomnd // It's max value.
	log.Panic(err, "random wrong")

	str := fmt.Sprintf("%03d", result.Int64()+1)
	if missingNums := confirmationCodeLength - len(str); missingNums > 0 {
		str = strings.Repeat("0", missingNums) + str
	}
	a.concurrentlyGeneratedCodes[opt].Store(userID, str)
	return str
}
func (a *accounts) generateAuthentifcatorSecret(opt TwoFAOptionEnum, userID string) string {
	if alreadyGeneratedCode, alreadyGenerated := a.concurrentlyGeneratedCodes[opt].Load(userID); alreadyGenerated {
		return alreadyGeneratedCode.(string)
	}
	const length = 10
	secret := make([]byte, length)
	gen, err := rand.Read(secret)
	if err != nil || gen != length {
		if gen != length {
			err = errors.Errorf("unexpected length: %v instead of %v", gen, length)
		}
		log.Panic(err, "random wrong")
	}
	encoded := base64.StdEncoding.EncodeToString(secret)
	a.concurrentlyGeneratedCodes[opt].Store(userID, encoded)
	return encoded
}

func (a *accounts) deliverCode(ctx context.Context, opt TwoFAOptionEnum, code, language string, deliverTo string) (*string, error) {
	var codeDeliverer interface {
		DeliverCode(ctx context.Context, code, language string, deliverTo string) error
	}
	switch opt {
	case TwoFAOptionTOTPAuthenticator:
		uri := a.totpProvider.GenerateURI(code, deliverTo)
		return &uri, nil
	case TwoFAOptionEmail:
		codeDeliverer = a.emailSender
	case TwoFAOptionSMS:
		codeDeliverer = a.smsSender
	default:
		log.Panic(errors.Errorf("unsupported 2FA provider %v", opt))
	}
	if codeDeliverer != nil {
		return nil, errors.Wrapf(codeDeliverer.DeliverCode(ctx, code, language, deliverTo), "failed to deliver 2fa code to %v using %v", deliverTo, opt)
	}
	return nil, errors.Errorf("unsupported 2FA provider %v", opt)
}

func (a *accounts) checkDeliveryChannelFor2FA(ctx context.Context, usr *user, opt TwoFAOptionEnum, newChannel *string) (string, error) {
	var existingDeliveryChannel string
	if usr != nil {
		switch {
		case opt == TwoFAOptionEmail && len(usr.Email) > 0 && usr.Active2FAEmail != nil:
			existingDeliveryChannel = usr.Email[*usr.Active2FAEmail]
		case opt == TwoFAOptionSMS && len(usr.PhoneNumber) > 0 && usr.Active2FAPhoneNumber != nil:
			existingDeliveryChannel = usr.PhoneNumber[*usr.Active2FAPhoneNumber]
		case opt == TwoFAOptionTOTPAuthenticator:
			switch {
			case len(usr.Email) > 0:
				existingDeliveryChannel = fmt.Sprintf("%v-%v", usr.Username, len(usr.TotpAuthenticatorSecret)+1)
			case len(usr.PhoneNumber) > 0:
				existingDeliveryChannel = fmt.Sprintf("%v-%v", usr.Username, len(usr.TotpAuthenticatorSecret)+1)
			default:
				return "", ErrAuthenticatorRequirementsNotMet
			}
			if len(usr.TotpAuthenticatorSecret) > 0 {
				return existingDeliveryChannel, Err2FARequired
			}
		}
		if newChannel != nil && len(existingDeliveryChannel) > 0 && existingDeliveryChannel != *newChannel {
			return *newChannel, Err2FARequired
		}
	}
	if len(existingDeliveryChannel) > 0 {
		return existingDeliveryChannel, nil
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

func (a *accounts) Delete2FA(ctx context.Context, userID string, inputCodes map[TwoFAOptionEnum]string, channel TwoFAOptionEnum, delValue string) error {
	usr, err := a.getUserByID(ctx, userID)
	if err != nil {
		return errors.Wrapf(err, "failed to check existing user phone and email for userID %v", userID)
	}
	if err = checkIfAll2FAProvided(usr, inputCodes); err != nil {
		return err
	}
	now := time.Now()
	var codes map[TwoFAOptionEnum]*twoFACode
	if codes, err = a.verify2FA(ctx, now, userID, inputCodes); err != nil {
		return errors.Wrapf(err, "falied to verify codes")
	}
	if err = a.canRemoveEmailOrPhoneDueToauthenticatorSetup(channel, usr, delValue); err != nil {
		return errors.Wrapf(err, "need to remove authenticator first")
	}
	_, err = a.updateUserWithDeleted2FA(ctx, now, usr, codes, channel, delValue)

	return errors.Wrapf(err, "failed to update user with 2fa removal %v %v %v", userID, channel, delValue)
}

func checkIfAll2FAProvided(usr *user, codes map[TwoFAOptionEnum]string) (err error) {
	twoFARequired := make([]TwoFAOptionEnum, 0, len(AllTwoFAOptions))
	for _, o := range AllTwoFAOptions {
		if err = checkIf2FARequired(usr, o, codes); err != nil {
			twoFARequired = append(twoFARequired, o)
		}
	}
	if len(twoFARequired) > 0 {
		return terror.New(Err2FARequired, map[string]any{
			"options": twoFARequired,
		})
	}
	return nil
}

func checkIf2FARequired(usr *user, opt TwoFAOptionEnum, codes map[TwoFAOptionEnum]string) error {
	var field []string
	var enabledIdx *int
	switch opt {
	case TwoFAOptionEmail:
		field = usr.Email
		enabledIdx = usr.Active2FAEmail
	case TwoFAOptionSMS:
		field = usr.PhoneNumber
		enabledIdx = usr.Active2FAPhoneNumber
	case TwoFAOptionTOTPAuthenticator:
		field = usr.TotpAuthenticatorSecret
		enabledIdx = usr.Active2FATotpAuthenticator
	default:
		log.Panic(errors.Errorf("unknown 2FA option %v", opt))
	}
	if len(field) > 0 && enabledIdx != nil {
		if _, presented := codes[opt]; !presented {
			return Err2FARequired
		}
	}
	return nil
}

func (a *accounts) canRemoveEmailOrPhoneDueToauthenticatorSetup(channel TwoFAOptionEnum, usr *user, removal string) error {
	if len(usr.TotpAuthenticatorSecret) == 0 {
		return nil
	}
	if channel == TwoFAOptionEmail && len(usr.Email) == 1 && len(usr.PhoneNumber) == 0 && slices.Contains(usr.Email, removal) {
		return ErrAuthenticatorRequirementsNotMet
	}
	if channel == TwoFAOptionSMS && len(usr.PhoneNumber) == 1 && len(usr.Email) == 0 && slices.Contains(usr.PhoneNumber, removal) {
		return ErrAuthenticatorRequirementsNotMet
	}
	return nil
}
