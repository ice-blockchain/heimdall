// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	stdlibtime "time"

	"github.com/goccy/go-json"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/terror"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) Verify2FA(ctx context.Context, userID string, userInputCodes map[TwoFAOptionWithAddr]string) error {
	_, err := a.verifyAndRedeem2FA(ctx, userID, userInputCodes)
	return errors.Wrapf(err, "failed to update codes as redeemed")
}
func (a *accounts) verifyAndRedeem2FA(ctx context.Context, userID string, userInputCodes map[TwoFAOptionWithAddr]string) (rollback map[TwoFAOptionWithAddr]string, err error) {
	now := time.Now()
	usr, err := a.getUserByID(ctx, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user for userID %v", userID)
	}
	var codes []*twoFACode
	if codes, err = a.verify2FA(ctx, now, usr, userInputCodes); err != nil {
		return nil, errors.Wrapf(err, "falied to verify codes")
	}

	return a.updateUserWithConfirmed2FA(ctx, now, userID, codes)
}

func (a *accounts) verify2FA(ctx context.Context, now *time.Time, usr *user, inputCodes map[TwoFAOptionWithAddr]string) ([]*twoFACode, error) {
	codes, err := a.get2FACodes(ctx, usr, inputCodes, now)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get pending codes %v for userID %v", inputCodes, usr.ID)
	}
	var vErr error
	faultCode := ""
	i := 0
	inputLen := len(inputCodes)
	for _, c := range codes {
		if i >= inputLen {
			break
		}
		t := twoFAOptionWithAddrFromCode(c)
		for input, inputCode := range inputCodes {
			if (inputCode == a.getCode(c, now, input.idx)) && input.opt == c.Option {
				input.addr = c.DeliverTo
				t.idx = input.idx
				inputCodes[input] = inputCode
			}
		}
		if vErr = c.expired(a, now); vErr != nil {
			break
		}
		if vErr = c.invalidCode(a, now, inputCodes, t); vErr != nil {
			faultCode = inputCodes[t]

			break
		}
		i++
	}

	return codes, errors.Wrapf(vErr, "failed to verify 2FA code \"%v\"", faultCode)
}

func (a *accounts) rollbackRedeemed2FACodes(usrID string, codes map[TwoFAOptionWithAddr]string) error {
	if len(codes) == 0 {
		return nil
	}
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
func (c *twoFACode) invalidCode(a *accounts, now *time.Time, inputCodes map[TwoFAOptionWithAddr]string, key TwoFAOptionWithAddr) error {
	invalidCode := false
	inputCode := inputCodes[key]
	switch c.Option {
	case TwoFAOptionEmail, TwoFAOptionSMS:
		invalidCode = c.Code != inputCode
	case TwoFAOptionTOTPAuthenticator:
		secrets := strings.Split(c.Code, ":")
		if key.idx >= len(secrets) {
			return errors.Wrapf(Err2FAInvalidCode, "invalid index %v", key.idx)
		}
		invalidCode = !(a.totpProvider.Verify(now, secrets[key.idx], inputCode))
	}
	if invalidCode {
		return Err2FAInvalidCode
	}

	return nil
}

func (a *accounts) getCode(c *twoFACode, now *time.Time, idx int) string {
	switch c.Option {
	case TwoFAOptionEmail, TwoFAOptionSMS:
		return c.Code
	case TwoFAOptionTOTPAuthenticator:
		secrets := strings.Split(c.Code, ":")
		if idx >= len(secrets) {
			return ""
		}
		return a.totpProvider.GenerateCode(now, secrets[idx])
	}
	return ""
}

func (a *accounts) updateUserWithConfirmed2FA(ctx context.Context, now *time.Time, userID string, codes []*twoFACode) (codesToRollback map[TwoFAOptionWithAddr]string, err error) {
	addEmailClause := "(case when users.email @> ARRAY[collapsed.email] then users.email else array_append(users.email,collapsed.email) end) "
	addPhoneClause := "(case when users.phone_number @> ARRAY[collapsed.phone_number] then users.phone_number else array_append(users.phone_number,collapsed.phone_number) end)"
	addTotpClause := "(case when users.totp_authenticator_secret @> ARRAY[collapsed.totp_authenticator_secret] then users.totp_authenticator_secret else array_append(users.totp_authenticator_secret,collapsed.totp_authenticator_secret) end)"
	return a.updateUserWithConfirmedOrDeleted2FA(ctx, now, userID, codes, "", -1, addEmailClause, addPhoneClause, addTotpClause)
}

func (a *accounts) updateUserWithDeleted2FA(ctx context.Context, now *time.Time, usr *user, confirmedRemovalByCodes []*twoFACode, removableOption TwoFAOptionEnum, removable2FAValue string) (codesToRollback map[TwoFAOptionWithAddr]string, err error) {
	removeEmailClause := "users.email"
	removePhoneClause := "users.phone_number"
	removeTotpClause := "users.totp_authenticator_secret"
	contains := false
	idx := 0
	switch removableOption {
	case TwoFAOptionEmail:
		removeEmailClause = "array_remove(users.email, $4)"
		idx = slices.Index(usr.Email, removable2FAValue)
		contains = idx != -1
	case TwoFAOptionSMS:
		removePhoneClause = "array_remove(users.phone_number, $4)"
		idx = slices.Index(usr.PhoneNumber, removable2FAValue)
		contains = idx != -1
	case TwoFAOptionTOTPAuthenticator:
		removeTotpClause = "array_remove(users.totp_authenticator_secret, $4)"
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
	return a.updateUserWithConfirmedOrDeleted2FA(ctx, now, usr.ID, confirmedRemovalByCodes, removable2FAValue, idx+1, removeEmailClause, removePhoneClause, removeTotpClause)
}

func (a *accounts) updateUserWithConfirmedOrDeleted2FA(
	ctx context.Context,
	now *time.Time,
	userID string,
	codes []*twoFACode,
	removal string,
	removalIdx int,
	addOrRemoveEmailClause, addOrRemovePhoneClause, addOrRemoveTotpClause string,
) (codesToRollback map[TwoFAOptionWithAddr]string, err error) {
	if len(codes) == 0 {
		return map[TwoFAOptionWithAddr]string{}, nil
	}
	whereClause, extraParams := buildWhereClauseRedeemCodes(codes)
	authenticatorCode := ""
	for _, c := range codes {
		if c.Option == TwoFAOptionTOTPAuthenticator {
			authenticatorCode = c.Code
			break
		}
	}
	params := []any{userID, *now.Time, authenticatorCode, removal, removalIdx}
	params = append(params, extraParams...)
	sql := fmt.Sprintf(`
WITH upd AS (
    UPDATE twofa_codes SET
        confirmed_at = $2,
        code = user_id
        WHERE user_id = $1 AND (%v)
        RETURNING
            user_id as user_id,
            option,
			deliver_to,
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
    	   active_2fa_email = CASE WHEN (NOT (COALESCE(users.email,ARRAY[]::TEXT[]) @> ARRAY[collapsed.email]) and collapsed.email is not null) THEN array_append(users.active_2fa_email, true) WHEN users.email @> ARRAY[$4] THEN users.active_2fa_email[1:$5-1]||users.active_2fa_email[$5+1:2147483647] ELSE users.active_2fa_email END ,
           active_2fa_phone_number = CASE WHEN (NOT(COALESCE(users.phone_number,ARRAY[]::TEXT[]) @> ARRAY[collapsed.phone_number]) and collapsed.phone_number is not null) THEN array_append(users.active_2fa_phone_number, true) WHEN users.phone_number @> ARRAY[$4] THEN users.active_2fa_phone_number[1:$5-1]||users.active_2fa_phone_number[$5+1:2147483647] ELSE users.active_2fa_phone_number END,
           active_2fa_totp_authenticator = CASE WHEN NULLIF (collapsed.totp_authenticator_secret,users.id) IS NOT NULL THEN array_append(users.active_2fa_totp_authenticator, true) WHEN users.totp_authenticator_secret @> ARRAY[$4] THEN users.active_2fa_totp_authenticator[1:$5-1]||users.active_2fa_totp_authenticator[$5+1:2147483647]ELSE users.active_2fa_totp_authenticator END
	FROM collapsed
	WHERE users.id = $1
	returning users.id
)
SELECT upd.option as option, upd.deliver_to as deliver_to from upd
inner join upd_users on upd.user_id = upd_users.id;`, whereClause, TwoFAOptionTOTPAuthenticator, addOrRemoveEmailClause, addOrRemovePhoneClause, addOrRemoveTotpClause)
	res, err := storage.ExecMany[struct {
		Option    TwoFAOptionEnum `db:"option"`
		DeliverTo string          `db:"deliver_to"`
	}](ctx, a.db, sql, params...)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to update user with 2FA passed")
	}
	codesForRollback := make(map[TwoFAOptionWithAddr]string, len(codes))
	if len(res) != len(codes) {
		missing := make([]TwoFAOptionWithAddr, 0, len(codes)-len(res))
		for _, c := range codes {
			f := false
			for _, r := range res {
				if c.Option == r.Option && c.DeliverTo == r.DeliverTo {
					f = true
					codesForRollback[twoFAOptionWithAddr(r.Option, r.DeliverTo, 0)] = c.Code
				}
			}
			if !f && c.Option != TwoFAOptionTOTPAuthenticator {
				missing = append(missing, twoFAOptionWithAddrFromCode(c))
			}
		}
		if len(missing) > 0 {
			log.Error(a.rollbackRedeemed2FACodes(userID, codesForRollback))
			return nil, Err2FAInvalidCode
		}
	}
	return codesForRollback, nil
}

func buildWhereClauseRedeemCodes(codes []*twoFACode) (string, []any) {
	where := make([]string, 0, len(codes))
	params := make([]any, 0, len(codes)*3)
	nextIndex := 6
	for _, c := range codes {
		where = append(where, fmt.Sprintf("(option = $%[1]v::twofa_option and deliver_to = $%[2]v and code = $%[3]v )", nextIndex, nextIndex+1, nextIndex+2))
		params = append(params, c.Option, c.DeliverTo, c.Code)
		nextIndex += 3
	}
	return strings.Join(where, " OR "), params
}

func buildWhereClauseGetCodes(usr *user, codes map[TwoFAOptionWithAddr]string) (string, []any, error) {
	if len(codes) == 0 {
		return "1=1", nil, nil
	}
	where := make([]string, 0, len(codes))
	params := make([]any, 0, len(codes)*2)
	nextIndex := 2
	for c := range codes {
		deliveryChannel, err := resolveDeliver(usr, codes, c)
		if err != nil {
			return "", nil, errors.Wrapf(err, "failed to map idx to value")
		}
		if deliveryChannel == "" || c.opt == TwoFAOptionTOTPAuthenticator { // Adding first.
			where = append(where, fmt.Sprintf("(option = $%[1]v)", nextIndex))
			params = append(params, c.opt)
			nextIndex += 1
		} else {
			where = append(where, fmt.Sprintf("(option = $%[1]v and (deliver_to = $%[2]v))", nextIndex, nextIndex+1))
			params = append(params, c.opt, deliveryChannel)
			nextIndex += 2
		}
	}
	return strings.Join(where, " OR "), params, nil
}

func resolveDeliver(usr *user, codes map[TwoFAOptionWithAddr]string, c TwoFAOptionWithAddr) (string, error) {
	switch c.opt {
	case TwoFAOptionEmail:
		if len(usr.Email) == 0 || len(codes) == 1 {
			return "", nil
		}
		if c.idx >= len(usr.Email) {
			return "", errors.Wrapf(Err2FAInvalidCode, "invalid index %v for %v", c.idx, TwoFAOptionEmail)
		}
		return usr.Email[c.idx], nil
	case TwoFAOptionSMS:
		if len(usr.PhoneNumber) == 0 || len(codes) == 1 {
			return "", nil
		}
		if c.idx >= len(usr.Email) {
			return "", errors.Wrapf(Err2FAInvalidCode, "invalid index %v for %v", c.idx, TwoFAOptionSMS)
		}
		return usr.PhoneNumber[c.idx], nil
	case TwoFAOptionTOTPAuthenticator:
		if len(usr.TotpAuthenticatorSecret) == 0 || len(codes) == 1 {
			return "", nil
		}
		if c.idx >= len(usr.TotpAuthenticatorSecret) {
			return "", errors.Wrapf(Err2FAInvalidCode, "invalid index %v for %v", c.idx, TwoFAOptionTOTPAuthenticator)
		}
		return usr.TotpAuthenticatorSecret[c.idx], nil
	default:
		return "", errors.Errorf("invalid 2FA method: %v", c.opt)
	}
}

func buildRollbackClause(codes map[TwoFAOptionWithAddr]string) (string, []any) {
	cases := make([]string, 0, len(codes))
	params := make([]any, 0, len(codes)*2)
	nextIndex := 3
	for k, v := range codes {
		cases = append(cases, fmt.Sprintf("WHEN option = $%[1]v AND deliver_to = $[2]v THEN $%[3]v", nextIndex, nextIndex+1, nextIndex+2))
		params = append(params, k.opt, k.addr, v)
		nextIndex += 3
	}
	return "CASE \n" + strings.Join(cases, "\n") + "\nEND", params
}

func (a *accounts) get2FACodes(ctx context.Context, usr *user, inputCodes map[TwoFAOptionWithAddr]string, now *time.Time) ([]*twoFACode, error) {
	params := []any{usr.ID}
	whereClause, extraParams, err := buildWhereClauseGetCodes(usr, inputCodes)
	params = append(params, extraParams...)
	sql := fmt.Sprintf(`SELECT created_at,
       			user_id,
			option,
			deliver_to,
			code,
			confirmed_at
    FROM (
		SELECT 
			twofa_codes.created_at as created_at,
			user_id,
			option,
			deliver_to,
			(case WHEN option = '%[1]v' THEN COALESCE(NULLIF(twofa_codes.code,u.id), array_to_string(u.totp_authenticator_secret,':')) ELSE twofa_codes.code END) as code,
			confirmed_at,
			(case WHEN option = '%[1]v' THEN NULLIF(twofa_codes.code,u.id) IS NULL ELSE false END) as totp_redeemed
		FROM twofa_codes 
		INNER JOIN users u on u.id = twofa_codes.user_id
		WHERE twofa_codes.user_id = $1 and (twofa_codes.code != twofa_codes.user_id OR twofa_codes.option = '%[1]v')) t
    WHERE (%[3]v)
    ORDER BY t.totp_redeemed ASC;`, TwoFAOptionTOTPAuthenticator, TwoFAOptionEmail, whereClause)
	codes, err := storage.Select[twoFACode](ctx, a.db, sql, params...)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to select 2fa codes")
	}

	if len(codes) != len(inputCodes) {
		i := len(inputCodes)
		dbc := len(codes)
		for ic := range inputCodes {
			if ic.opt == TwoFAOptionTOTPAuthenticator {
				i -= 1
			}
		}
		for _, ic := range codes {
			if ic.Option == TwoFAOptionTOTPAuthenticator {
				dbc -= 1
			}
		}
		if dbc < i {
			return nil, ErrNoPending2FA
		}
		codes = slices.DeleteFunc(codes, func(c *twoFACode) bool {
			matches := false
			for opt, ic := range inputCodes {
				if opt.opt == c.Option && (ic == a.getCode(c, now, opt.idx)) {
					matches = true
				}
			}

			return !matches
		})
		if len(codes) == 0 {
			return nil, ErrNoPending2FA
		}
	}

	return codes, nil
}

func (a *accounts) Send2FA(ctx context.Context, userIDOrUsername string, opt TwoFAOptionEnum, optDeliverTo *string, language string, existing2FAVerificationForModify map[TwoFAOptionWithAddr]string) (*string, error) {
	now := time.Now()
	var codesForRollback map[TwoFAOptionWithAddr]string
	var usr *user
	var err error
	if userSignature(ctx) == "" && authHeader(ctx) == "" {
		username := strings.ToLower(userIDOrUsername)
		usr, err = a.getUserByUsername(ctx, username)
	} else {
		usr, err = a.getUserByID(ctx, userIDOrUsername)
	}

	if err != nil {
		return nil, errors.Wrapf(err, "failed to check existing user phone and email for user %v", userIDOrUsername)
	}
	deliverTo, err := a.checkDeliveryChannelFor2FA(ctx, usr, opt, optDeliverTo)
	if err != nil {
		if !(errors.Is(err, Err2FARequired) || errors.Is(err, errSignatureRequired)) {
			return nil, errors.Wrapf(err, "failed to detect where to deviver 2fa")
		}
		if server.LoggedInUser(ctx) == nil {
			return nil, server.ErrInvalidToken
		}
		if sErr := a.verifyUserSignature(userSignature(ctx), now, usr); sErr != nil {
			return nil, errors.Wrapf(sErr, "invalid user signature on putting new 2fa")
		}
		if errors.Is(err, Err2FARequired) {
			if _, err = a.checkIfEnough2FAProvided(usr, existing2FAVerificationForModify); err != nil {
				return nil, err //nolint:wrapcheck // tErr.
			}
			codesForRollback, err = a.verifyAndRedeem2FA(ctx, usr.ID, existing2FAVerificationForModify)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to verify existing 2fa for user %v", usr.ID)
			}
		}
	}
	var code string
	if opt == TwoFAOptionTOTPAuthenticator {
		code = a.generateAuthentifcatorSecret(opt, usr.ID)
	} else {
		code = a.generateConfirmationCode(opt, usr.ID)
	}
	defer a.concurrentlyGeneratedCodes[opt].Delete(usr.ID)
	if uErr := a.upsert2FACode(ctx, &twoFACode{
		CreatedAt: now,
		UserID:    usr.ID,
		Option:    opt,
		DeliverTo: deliverTo,
		Code:      code,
	}); uErr != nil {
		return nil, multierror.Append(
			errors.Wrapf(uErr, "failed to upsert code for userID %v", usr.ID),
			errors.Wrapf(a.rollbackRedeemed2FACodes(usr.ID, codesForRollback), "[rollback] failed to rollback 2fa codes to approve modification for user %v", usr.ID),
		).ErrorOrNil()

	}

	authenticatorUri, dErr := a.deliverCode(ctx, opt, code, language, deliverTo)
	if dErr != nil {
		return nil, multierror.Append(
			errors.Wrapf(dErr, "failed to deliver 2fa code to user %v with %v:%v", usr.ID, opt, deliverTo),
			errors.Wrapf(a.rollbackRedeemed2FACodes(usr.ID, codesForRollback), "[rollback] failed to rollback 2fa codes to approve modification for user %v", usr.ID),
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

func enabled2FA(values []string, enabled []bool) ([]string, []int) {
	res := make([]string, 0, len(enabled))
	idx := make([]int, 0, len(enabled))
	for ix, flag := range enabled {
		if flag {
			res = append(res, values[ix])
			idx = append(idx, ix)
		}
	}
	return res, idx
}

func (a *accounts) checkDeliveryChannelFor2FA(ctx context.Context, usr *user, opt TwoFAOptionEnum, newChannel *string) (string, error) {
	var existingDeliveryChannel []string
	if usr != nil {
		switch {
		case opt == TwoFAOptionEmail && len(usr.Email) > 0 && usr.Active2FAEmail != nil:
			enabled, _ := enabled2FA(usr.Email, usr.Active2FAEmail)
			existingDeliveryChannel = append(existingDeliveryChannel, enabled...)
		case opt == TwoFAOptionSMS && len(usr.PhoneNumber) > 0 && usr.Active2FAPhoneNumber != nil:
			enabled, _ := enabled2FA(usr.PhoneNumber, usr.Active2FAPhoneNumber)
			existingDeliveryChannel = append(existingDeliveryChannel, enabled...)
		case opt == TwoFAOptionTOTPAuthenticator:
			var totpName string
			switch {
			case len(usr.Email) > 0:
				totpName = fmt.Sprintf("%v-%v", usr.Username, len(usr.TotpAuthenticatorSecret)+1)
			case len(usr.PhoneNumber) > 0:
				totpName = fmt.Sprintf("%v-%v", usr.Username, len(usr.TotpAuthenticatorSecret)+1)
			default:
				return "", ErrAuthenticatorRequirementsNotMet
			}
			if len(usr.TotpAuthenticatorSecret) > 0 {
				return totpName, Err2FARequired
			} else {
				return totpName, nil
			}
		}
		if newChannel != nil && len(existingDeliveryChannel) > 0 && !slices.Contains(existingDeliveryChannel, *newChannel) {
			return *newChannel, Err2FARequired
		}
	}
	if len(existingDeliveryChannel) > 0 {
		if len(existingDeliveryChannel) == 1 || newChannel == nil {
			return existingDeliveryChannel[len(existingDeliveryChannel)-1], nil
		} else {
			return *newChannel, nil
		}
	}
	if newChannel == nil {
		return "", Err2FADeliverToNotProvided
	}

	return *newChannel, errSignatureRequired

}

func (a *accounts) upsert2FACode(ctx context.Context, codeInfo *twoFACode) error {
	sql := `INSERT INTO twofa_codes (created_at, user_id, option, deliver_to, code) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (user_id, option, deliver_to) DO UPDATE SET
                                            created_at = excluded.created_at,
                                            code = excluded.code
			WHERE twofa_codes.code != excluded.code OR twofa_codes.deliver_to != excluded.deliver_to;`
	_, err := storage.Exec(ctx, a.db, sql, codeInfo.CreatedAt, codeInfo.UserID, codeInfo.Option, codeInfo.DeliverTo, codeInfo.Code)

	return errors.Wrapf(err, "failed to upsert in-progress 2fa code info for userID %v %#v", codeInfo.UserID, codeInfo)
}

func (a *accounts) Delete2FA(ctx context.Context, userID string, inputCodes map[TwoFAOptionWithAddr]string, channel TwoFAOptionEnum, delValue string) error {
	now := time.Now()
	usr, err := a.getUserByID(ctx, userID)
	if err != nil {
		return errors.Wrapf(err, "failed to check existing user phone and email for userID %v", userID)
	}
	if err = a.verifyUserSignature(userSignature(ctx), now, usr); err != nil {
		return errors.Wrap(err, "invalid user signature on deleting existing 2fa")
	}
	if _, err = a.checkIfEnough2FAProvided(usr, inputCodes); err != nil {
		return err
	}
	var codes []*twoFACode
	if codes, err = a.verify2FA(ctx, now, usr, inputCodes); err != nil {
		return errors.Wrapf(err, "falied to verify codes")
	}
	if err = a.canRemoveEmailOrPhoneDueToauthenticatorSetup(channel, usr, delValue); err != nil {
		return errors.Wrapf(err, "need to remove authenticator first")
	}
	_, err = a.updateUserWithDeleted2FA(ctx, now, usr, codes, channel, delValue)

	return errors.Wrapf(err, "failed to update user with 2fa removal %v %v %v", userID, channel, delValue)
}

func (a *accounts) checkIfEnough2FAProvided(usr *user, codes map[TwoFAOptionWithAddr]string) (enabled bool, err error) {
	enabledOptions := map[TwoFAOptionWithAddr]bool{}
	for _, o := range AllTwoFAOptions {
		switch o {
		case TwoFAOptionEmail:
			_, enabledIdx := enabled2FA(usr.Email, usr.Active2FAEmail)
			for _, ix := range enabledIdx {
				enabledOptions[twoFAOptionWithIdx(TwoFAOptionEmail, ix)] = true
			}

		case TwoFAOptionSMS:
			_, enabledIdx := enabled2FA(usr.PhoneNumber, usr.Active2FAPhoneNumber)
			for _, ix := range enabledIdx {
				enabledOptions[twoFAOptionWithIdx(TwoFAOptionSMS, ix)] = true
			}

		case TwoFAOptionTOTPAuthenticator:
			_, enabledIdx := enabled2FA(usr.TotpAuthenticatorSecret, usr.Active2FATotpAuthenticator)
			for _, ix := range enabledIdx {
				enabledOptions[twoFAOptionWithIdx(TwoFAOptionTOTPAuthenticator, ix)] = true
			}
		}
	}
	presentedOptionsCount := 0
	enabledCount := len(enabledOptions)
	for o := range enabledOptions {
		if _, presented := codes[o]; presented {
			delete(enabledOptions, o)
			presentedOptionsCount += 1
		}
	}
	if presentedOptionsCount < a.cfg.Max2FACount {
		if len(enabledOptions) <= a.cfg.Max2FACount && presentedOptionsCount >= len(enabledOptions) {
			return enabledCount > 0, nil
		}
		err = terror.New(Err2FARequired, map[string]any{
			"n": int(math.Min(float64(a.cfg.Max2FACount), float64(len(enabledOptions)))),
		})
	}

	return enabledCount > 0, err
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

func userSignature(ctx context.Context) string {
	val := ctx.Value(UserSignatureCtxValueKey)
	if val == nil {
		return ""
	}
	return val.(string)
}
func authHeader(ctx context.Context) string {
	val := ctx.Value(AuthorizationHeaderCtxValue)
	if val == nil {
		return ""
	}
	return val.(string)
}

func (a *accounts) verifyUserSignature(b64 string, now *time.Time, usr *user) error {
	// signature(hex):createdAtTS:userID
	signatureStringBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return errors.Wrapf(ErrInvalidUserSignature, "incorrect base64")
	}
	signatureEnd := bytes.IndexByte(signatureStringBytes, ':')
	if signatureEnd == -1 {
		return errors.Wrapf(ErrInvalidUserSignature, "incorrect signature, cant detect signature")
	}
	signature, err := hex.DecodeString(string(signatureStringBytes[:signatureEnd]))
	if err != nil {
		return errors.Wrapf(ErrInvalidUserSignature, "incorrect signture is not base64 encoded")
	}
	createdAtEnd := bytes.IndexByte(signatureStringBytes[signatureEnd+1:], ':')
	if createdAtEnd == -1 {
		return errors.Wrapf(ErrInvalidUserSignature, "incorrect signature, cant detect createdAt")
	}
	createdAtUnix, err := strconv.ParseInt(string(signatureStringBytes[signatureEnd+1:signatureEnd+1+createdAtEnd]), 10, 64)
	if err != nil {
		return errors.Wrapf(ErrInvalidUserSignature, "incorrect signature, invalid createdAt %v", string(signatureStringBytes[:createdAtEnd]))
	}
	createdAt := stdlibtime.Unix(createdAtUnix, 0)
	if createdAt.After(*now.Time) || now.Sub(createdAt) > a.cfg.UserSignatureExpiration {
		return errors.Wrapf(ErrInvalidUserSignature, "expired createdAt")
	}
	hash := sha256.New()
	if _, err = fmt.Fprintf(hash, "%v:%v", createdAtUnix, usr.ID); err != nil {
		return errors.Wrapf(err, "failed to build sha256 hash")
	}
	signedData := hash.Sum(nil)

	pubkey, err := hex.DecodeString(usr.MasterPubKey)
	if err != nil {
		return errors.Wrapf(ErrInvalidUserSignature, "user %v have invalid master pubkey", usr.ID)
	}
	if !ed25519.Verify(pubkey, signedData, signature) {
		return ErrInvalidUserSignature
	}

	return nil
}

func (t *TwoFAOptionWithAddr) UnmarshalText(b []byte) (err error) {
	return t.UnmarshalParam(string(b))
}
func (t *TwoFAOptionWithAddr) MarshalJSON() (b []byte, err error) {
	return json.Marshal(t.String())
}

func (t *TwoFAOptionWithAddr) UnmarshalParam(s string) error {
	idx := strings.IndexByte(s, ':')
	if idx == -1 {
		t.idx = 0
		t.opt = TwoFAOptionEnum(s)
		return nil
	}
	t.opt = TwoFAOptionEnum(s[:idx])
	deliveryTo, err := strconv.ParseInt(s[idx+1:], 10, 64)
	if err != nil {
		return errors.Wrapf(err, "failed to unmarshal TwoFAOptionWithAddr")
	}
	t.idx = int(deliveryTo)

	return nil
}

func (t *TwoFAOptionWithAddr) String() string {
	if t.addr == "" {
		if t.idx == 0 {
			return fmt.Sprintf("%v", t.opt)
		}
		return fmt.Sprintf("%v:%v", t.opt, t.idx)
	} else {
		return fmt.Sprintf("%v:%v", t.opt, t.addr)
	}
}

func (t TwoFAOptionEnum) Validate() error {
	for _, opt := range AllTwoFAOptions {
		if t == opt {
			return nil
		}
	}
	return errors.Errorf("invalid 2fa option: %v", t)
}

func twoFAOptionWithIdx(opt TwoFAOptionEnum, addrIdx int) TwoFAOptionWithAddr {
	return TwoFAOptionWithAddr{opt: opt, idx: addrIdx}
}
func twoFAOptionWithAddr(opt TwoFAOptionEnum, addr string, idx int) TwoFAOptionWithAddr {
	return TwoFAOptionWithAddr{opt: opt, addr: addr, idx: idx}
}
func twoFAOptionWithAddrFromCode(c *twoFACode) TwoFAOptionWithAddr {
	return TwoFAOptionWithAddr{opt: c.Option, addr: c.DeliverTo, idx: 0}
}

func (t *TwoFAOptionWithAddr) Validate() error {
	return t.opt.Validate()
}
