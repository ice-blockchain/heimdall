// SPDX-License-Identifier: ice License 1.0

// Package api Code generated by swaggo/swag. DO NOT EDIT
package api

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "ice.io",
            "url": "https://ice.io"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/auth/recover/user/delegated": {
            "post": {
                "description": "Initiates recovery process with dfns",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Recovery"
                ],
                "parameters": [
                    {
                        "description": "Request params",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/main.StartDelegatedRecoveryReq"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/main.StartDelegatedRecoveryResp"
                        }
                    },
                    "400": {
                        "description": "if invalid 2FA code is provided",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    },
                    "403": {
                        "description": "if 2FA required",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    },
                    "504": {
                        "description": "if request times out",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/auth/users/{userId}": {
            "get": {
                "description": "Initiates recovery process with dfns",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Users"
                ],
                "parameters": [
                    {
                        "type": "string",
                        "description": "ID of the user",
                        "name": "userId",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "default": "Bearer \u003cAdd token here\u003e",
                        "description": "Dfns token",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/main.User"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/main.dfnsErrorResponse"
                        }
                    },
                    "504": {
                        "description": "if request times out",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/v1/users/{userId}/2fa/{twoFAOption}/verification-requests": {
            "put": {
                "description": "Verifies 2FA code from the user",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "2FA"
                ],
                "parameters": [
                    {
                        "type": "string",
                        "description": "ID of the user",
                        "name": "userId",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "type of 2fa (sms/email/google_authentificator)",
                        "name": "twoFAOption",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "code from second factor",
                        "name": "code",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/main.Verify2FARequestResp"
                        }
                    },
                    "400": {
                        "description": "if code is invalid or expired",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    },
                    "409": {
                        "description": "if there is no pending 2FA verification",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    },
                    "504": {
                        "description": "if request times out",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    }
                }
            },
            "post": {
                "description": "Initiates sending of 2FA code to the user",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "2FA"
                ],
                "parameters": [
                    {
                        "type": "string",
                        "default": "",
                        "description": "Language",
                        "name": "X-Language",
                        "in": "header"
                    },
                    {
                        "type": "string",
                        "description": "ID of the user",
                        "name": "userId",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "type of 2fa (sms/email/google_authentificator)",
                        "name": "twoFAOption",
                        "in": "path",
                        "required": true
                    },
                    {
                        "description": "Request params containing email or phone number to set up 2FA",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/main.Send2FARequestReq"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/main.Send2FARequestResp"
                        }
                    },
                    "400": {
                        "description": "if user's email / phone number is not provided",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    },
                    "403": {
                        "description": "if user already have 2FA set up, and it is requested for new email / phone",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    },
                    "504": {
                        "description": "if request times out",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/v1/users/{userId}/ion-connect-indexers": {
            "get": {
                "description": "Returns indexers list for the user",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Users"
                ],
                "parameters": [
                    {
                        "type": "string",
                        "description": "ID of the user",
                        "name": "userId",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "default": "Bearer \u003cAdd token here\u003e",
                        "description": "Dfns token",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/main.Relays"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    },
                    "504": {
                        "description": "if request times out",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/v1/users/{userId}/ion-connect-relays": {
            "post": {
                "description": "Assigns relay list for the user based on his followee list",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Users"
                ],
                "parameters": [
                    {
                        "type": "string",
                        "description": "ID of the user",
                        "name": "userId",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "default": "Bearer \u003cAdd token here\u003e",
                        "description": "Dfns token",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    },
                    {
                        "description": "Request params",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/main.RelaysReq"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/main.Relays"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    },
                    "504": {
                        "description": "if request times out",
                        "schema": {
                            "$ref": "#/definitions/server.ErrorResponse"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "accounts.TwoFAOptionEnum": {
            "type": "string",
            "enum": [
                "sms",
                "email",
                "google_authentificator"
            ],
            "x-enum-varnames": [
                "TwoFAOptionSMS",
                "TwoFAOptionEmail",
                "TwoFAOptionTOTPAuthentificator"
            ]
        },
        "dfns.Permission": {
            "type": "object",
            "properties": {
                "dateCreated": {
                    "type": "string"
                },
                "dateUpdated": {
                    "type": "string"
                },
                "id": {
                    "type": "string"
                },
                "isArchived": {
                    "type": "boolean"
                },
                "isImmutable": {
                    "type": "boolean"
                },
                "name": {
                    "type": "string"
                },
                "operations": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "status": {
                    "type": "string"
                }
            }
        },
        "dfns.PermissionAssignment": {
            "type": "object",
            "properties": {
                "assignmentId": {
                    "type": "string"
                },
                "operations": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "permissionId": {
                    "type": "string"
                },
                "permissionName": {
                    "type": "string"
                }
            }
        },
        "main.Relays": {
            "type": "object",
            "properties": {
                "ionConnectRelays": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                }
            }
        },
        "main.RelaysReq": {
            "type": "object",
            "properties": {
                "followeeList": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                }
            }
        },
        "main.Send2FARequestReq": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string"
                },
                "phoneNumber": {
                    "type": "string"
                }
            }
        },
        "main.Send2FARequestResp": {
            "type": "object",
            "properties": {
                "TOTPAuthentificatorURL": {
                    "type": "string"
                }
            }
        },
        "main.StartDelegatedRecoveryReq": {
            "type": "object",
            "properties": {
                "2FAVerificationCodes": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "string"
                    }
                },
                "credentialId": {
                    "type": "string"
                },
                "username": {
                    "type": "string"
                }
            }
        },
        "main.StartDelegatedRecoveryResp": {
            "type": "object",
            "properties": {
                "allowedRecoveryCredentials": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "encryptedRecoveryKey": {
                                "type": "string"
                            },
                            "id": {
                                "type": "string"
                            }
                        }
                    }
                },
                "attestation": {
                    "type": "string"
                },
                "authenticatorSelection": {
                    "type": "object",
                    "properties": {
                        "authenticatorAttachment": {
                            "type": "string"
                        },
                        "requireResidentKey": {
                            "type": "boolean"
                        },
                        "residentKey": {
                            "type": "string"
                        },
                        "userVerification": {
                            "type": "string"
                        }
                    }
                },
                "challenge": {
                    "type": "string"
                },
                "excludeCredentials": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string"
                            },
                            "transports": {
                                "type": "string"
                            },
                            "type": {
                                "type": "string"
                            }
                        }
                    }
                },
                "pubKeyCredParam": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "alg": {
                                "type": "integer"
                            },
                            "type": {
                                "type": "string"
                            }
                        }
                    }
                },
                "rp": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string"
                        },
                        "name": {
                            "type": "string"
                        }
                    }
                },
                "supportedCredentialKinds": {
                    "type": "object",
                    "properties": {
                        "firstFactor": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        "secondFactor": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        }
                    }
                },
                "temporaryAuthenticationToken": {
                    "type": "string"
                },
                "user": {
                    "type": "object",
                    "properties": {
                        "displayName": {
                            "type": "string"
                        },
                        "id": {
                            "type": "string"
                        },
                        "name": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "main.User": {
            "type": "object",
            "properties": {
                "2faOptions": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/accounts.TwoFAOptionEnum"
                    }
                },
                "credentialUuid": {
                    "type": "string"
                },
                "email": {
                    "type": "string"
                },
                "ionIndexers": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "ionRelays": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "isActive": {
                    "type": "boolean"
                },
                "isRegistered": {
                    "type": "boolean"
                },
                "isServiceAccount": {
                    "type": "boolean"
                },
                "kind": {
                    "type": "string"
                },
                "orgId": {
                    "type": "string"
                },
                "permissionAssignments": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/dfns.PermissionAssignment"
                    }
                },
                "permissions": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/dfns.Permission"
                    }
                },
                "phoneNumber": {
                    "type": "string"
                },
                "scopes": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "userId": {
                    "type": "string"
                },
                "username": {
                    "type": "string"
                }
            }
        },
        "main.Verify2FARequestResp": {
            "type": "object"
        },
        "main.dfnsErrorResponse": {
            "type": "object",
            "properties": {
                "data": {
                    "type": "object",
                    "additionalProperties": {}
                },
                "error": {
                    "$ref": "#/definitions/main.errMessage"
                }
            }
        },
        "main.errMessage": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string"
                }
            }
        },
        "server.ErrorResponse": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "example": "SOMETHING_NOT_FOUND"
                },
                "data": {
                    "type": "object",
                    "additionalProperties": {}
                },
                "error": {
                    "type": "string",
                    "example": "something is missing"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "latest",
	Host:             "",
	BasePath:         "",
	Schemes:          []string{"https"},
	Title:            "User accounts management for ION",
	Description:      "It is responsible for providing off chain account management for the ION Platform; it is the first layer of interaction between users and the platform.",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
