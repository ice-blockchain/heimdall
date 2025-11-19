// SPDX-License-Identifier: ice License 1.0

package server

import (
	"net/http"

	"github.com/pkg/errors"
)

func BadRequest(err error, code string, dataArg ...map[string]any) *ResponseError {
	return &ResponseError{
		Data: &ResponseErrorBody{
			Err:          err,
			ErrorMessage: err.Error(),
			Code:         code,
		},
		Code: http.StatusBadRequest,
	}
}

func UnprocessableEntity(err error, code string, dataArg ...map[string]any) *ResponseError {
	return &ResponseError{
		Data: &ResponseErrorBody{
			Err:          err,
			ErrorMessage: err.Error(),
			Code:         code,
		},
		Code: http.StatusUnprocessableEntity,
	}
}

func Conflict(err error, code string, dataArg ...map[string]any) *ResponseError {
	return &ResponseError{
		Data: &ResponseErrorBody{
			Err:          err,
			ErrorMessage: err.Error(),
			Code:         code,
		},
		Code: http.StatusConflict,
	}
}

func NotFound(err error, code string, dataArg ...map[string]any) *ResponseError {
	return &ResponseError{
		Data: &ResponseErrorBody{
			Err:          err,
			ErrorMessage: err.Error(),
			Code:         code,
		},
		Code: http.StatusNotFound,
	}
}

func Unexpected(err error) *ResponseError {
	return &ResponseError{
		Code: -1,
		Data: &ResponseErrorBody{
			Err:          err,
			ErrorMessage: err.Error(),
		},
	}
}

func Unauthorized(err error, dataArg ...map[string]any) *ResponseError {
	return &ResponseError{
		Code: http.StatusUnauthorized,
		Data: &ResponseErrorBody{
			Err:          errors.Wrapf(err, "authorization failed"),
			ErrorMessage: err.Error(),
			Code:         "INVALID_TOKEN",
		},
	}
}

func Forbidden(err error, dataArg ...map[string]any) *ResponseError {
	return &ResponseError{
		Code: http.StatusForbidden,
		Data: &ResponseErrorBody{
			Err:          err,
			ErrorMessage: err.Error(),
			Code:         "OPERATION_NOT_ALLOWED",
		},
	}
}

func ForbiddenWithCode(err error, code string, dataArg ...map[string]any) *ResponseError {
	return &ResponseError{
		Code: http.StatusForbidden,
		Data: &ResponseErrorBody{
			Err:          err,
			ErrorMessage: err.Error(),
			Code:         code,
		},
	}
}

func NoContent() *Response[any] {
	return &Response[any]{Code: http.StatusNoContent}
}

func Created[RESP any](resp *RESP) *Response[RESP] {
	return &Response[RESP]{Code: http.StatusCreated, Data: resp}
}
