// SPDX-License-Identifier: ice License 1.0

package main

import (
	"time"

	"github.com/ice-blockchain/heimdall/accounts"
)

type (
	StartDelegatedRecoveryReq struct {
		Username               string                     `json:"username"`
		CredentialID           string                     `json:"credentialId"`
		TwoFAVerificationCodes map[TwoFAOptionEnum]string `json:"2FAVerificationCodes"`
	}
	TwoFAOptionEnum            = accounts.TwoFAOptionEnum
	StartDelegatedRecoveryResp struct {
		Rp struct {
			Id   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		User struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
		TemporaryAuthenticationToken string `json:"temporaryAuthenticationToken"`
		SupportedCredentialKinds     struct {
			FirstFactor  []string `json:"firstFactor"`
			SecondFactor []string `json:"secondFactor"`
		} `json:"supportedCredentialKinds"`
		Challenge       string `json:"challenge"`
		PubKeyCredParam []struct {
			Type string `json:"type"`
			Alg  string `json:"alg"`
		} `json:"pubKeyCredParam"`
		Attestation        string `json:"attestation"`
		ExcludeCredentials []struct {
			Type       string `json:"type"`
			Id         string `json:"id"`
			Transports string `json:"transports"`
		} `json:"excludeCredentials"`
		AuthenticatorSelection struct {
			AuthenticatorAttachment string `json:"authenticatorAttachment"`
			ResidentKey             string `json:"residentKey"`
			RequireResidentKey      string `json:"requireResidentKey"`
			UserVerification        string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		AllowedRecoveryCredentials []struct {
			Id                   string `json:"id"`
			EncryptedRecoveryKey string `json:"encryptedRecoveryKey"`
		} `json:"allowedRecoveryCredentials"`
	}

	Send2FARequestReq struct {
		UserID      string          `uri:"userId" required:"true" swaggerignore:"true"`
		TwoFAOption TwoFAOptionEnum `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		Language    string          `header:"X-Language" swaggerignore:"true"`
		Email       *string         `json:"email,omitempty"`
		PhoneNumber *string         `json:"phoneNumber,omitempty"`
	}
	Send2FARequestResp struct {
		TOTPAuthentificatorURL *string `json:"TOTPAuthentificatorURL,omitempty"`
	}
	Verify2FARequestReq struct {
		UserID      string          `uri:"userId" required:"true"`
		TwoFAOption TwoFAOptionEnum `uri:"twoFAOption" required:"true"`
	}
	Verify2FARequestResp struct {
	}
)

const (
	applicationYamlKey         = "cmd/heimdall"
	proxyTimeout               = 30 * time.Second
	invalidPropertiesErrorCode = "INVALID_PROPERTIES"
	twoFAAlreadySetupErrorCode = "2FA_ALREADY_SETUP"
)

type (
	service struct {
		accounts accounts.Accounts
		cfg      *config
	}
	config struct {
		Host               string `yaml:"host"`
		Version            string `yaml:"version"`
		ProxyDfnsEndpoints []struct {
			Endpoint string `yaml:"endpoint"`
			Method   string `yaml:"method"`
		} `yaml:"proxyDfnsEndpoints"`
	}
)
