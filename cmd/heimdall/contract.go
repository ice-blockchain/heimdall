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
)

const (
	applicationYamlKey         = "cmd/heimdall"
	proxyTimeout               = 30 * time.Second
	invalidPropertiesErrorCode = "INVALID_PROPERTIES"
)

type (
	service struct {
		accounts accounts.Accounts
		cfg      *config
	}
	config struct {
		// TODO: swagger
		//Host               string `yaml:"host"`
		//Version            string `yaml:"version"`
		ProxyDfnsEndpoints []struct {
			Endpoint string `yaml:"endpoint"`
			Method   string `yaml:"method"`
		} `yaml:"proxyDfnsEndpoints"`
	}
)
