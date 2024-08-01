// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"net/http"
	"reflect"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/log"
)

type DfnsInternalError struct {
	raw        string
	HTTPStatus int                    `json:"httpStatus"`        // HTTP status code
	Message    string                 `json:"message"`           // Error message
	Context    map[string]interface{} `json:"context,omitempty"` // Additional context
}

func ParseErrAsDfnsInternalErr(err error) error {
	if err == nil {
		return nil
	}
	err = unwrap(err)
	var alreadyParsedDfnsErr *DfnsInternalError
	if errors.As(err, &alreadyParsedDfnsErr) {
		return alreadyParsedDfnsErr
	}
	errValue := reflect.ValueOf(err)
	if errValue.Type().String() == "*dfnsapiclient.DfnsError" {
		var dfnsErr DfnsInternalError
		dfnsErr.raw = err.Error()
		if jErr := json.Unmarshal([]byte(err.Error()), &dfnsErr); jErr != nil {
			return errors.Wrapf(jErr, "dfns sdk compatibility issue: unable to parse dfnsapiclient.DfnsError with %v as json", err.Error())
		}
		return &dfnsErr
	}
	return nil
}
func (d *DfnsInternalError) Error() string {
	return d.raw
}

func unwrap(err error) error {
	switch x := err.(type) {
	case interface{ Unwrap() error }:
		err = x.Unwrap()
		if err == nil {
			return nil
		}
		return unwrap(err)
	default:
		return err
	}
}

func passErrorInResponse(writer http.ResponseWriter, request *http.Request, err error) {
	if dfnsErr := ParseErrAsDfnsInternalErr(err); dfnsErr != nil {
		var dfnsParsedErr *DfnsInternalError
		if errors.As(dfnsErr, &dfnsParsedErr) {
			var body []byte
			var headers http.Header
			status := dfnsParsedErr.HTTPStatus
			if b, hasBody := dfnsParsedErr.Context["Body"]; hasBody {
				if body, err = json.Marshal(b.(map[string]interface{})); err != nil {
					// TODO
				}
			}
			if h, hasHeaders := dfnsParsedErr.Context["Header"]; hasHeaders {
				headers = h.(http.Header)
			}
			for k, hh := range headers {
				for _, h := range hh {
					writer.Header().Add(k, h)
				}
			}
			writer.WriteHeader(status)
			writer.Write(body)
			log.Error(errors.Errorf("dfns req to %v %v ended up with %v (data: %v)", request.Method, request.URL.Path, status, string(body)))
			return
		}
	}
	log.Error(errors.Errorf("dfns req to %v %v ended up with error", request.Method, request.URL.Path))
	writer.WriteHeader(http.StatusBadGateway)
}
