// SPDX-License-Identifier: ice License 1.0

package server

import (
	"net/http"
)

func Error(err error, errCode string, httpCode int) *ResponseError {
	resp := ResponseError{
		Data: &ResponseErrorBody{
			Err:          err,
			ErrorMessage: err.Error(),
			Code:         errCode,
		},
		Code: httpCode,
	}
	return &resp
}

func OK[RESP any](responses ...*RESP) *Response[RESP] {
	var resp *RESP
	if len(responses) == 1 {
		resp = responses[0]
	}

	return &Response[RESP]{Code: http.StatusOK, Data: resp}
}

func Raw(contentType string, responses ...[]byte) *Response[string] {
	var resp []byte
	if len(responses) == 1 {
		resp = responses[0]
	}

	return &Response[string]{Code: http.StatusOK, ContentType: contentType, Raw: resp}
}

func BadRequest(err error, code string, dataArg ...map[string]any) *ResponseError {
	return Error(err, code, http.StatusBadRequest)
}

func UnprocessableEntity(err error, code string, dataArg ...map[string]any) *ResponseError {
	return Error(err, code, http.StatusUnprocessableEntity)
}

func Conflict(err error, code string, dataArg ...map[string]any) *ResponseError {
	return Error(err, code, http.StatusConflict)
}

func NotFound(err error, code string, dataArg ...map[string]any) *ResponseError {
	return Error(err, code, http.StatusNotFound)
}

func Unauthorized(err error, dataArg ...map[string]any) *ResponseError {
	return Error(err, "INVALID_TOKEN", http.StatusUnauthorized)
}

func Forbidden(err error, dataArg ...map[string]any) *ResponseError {
	return Error(err, "OPERATION_NOT_ALLOWED", http.StatusForbidden)
}

func NoContent() *Response[any] {
	return &Response[any]{Code: http.StatusNoContent}
}

func Created[RESP any](resp *RESP) *Response[RESP] {
	return &Response[RESP]{Code: http.StatusCreated, Data: resp}
}
