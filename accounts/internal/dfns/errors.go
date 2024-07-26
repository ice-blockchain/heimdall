package dfns

import (
	"github.com/goccy/go-json"
	"github.com/ice-blockchain/wintr/log"
	"github.com/pkg/errors"
	"net/http"
	"reflect"
)

type dfnsInternalError struct {
	raw        string
	HTTPStatus int                    `json:"httpStatus"`        // HTTP status code
	Message    string                 `json:"message"`           // Error message
	Context    map[string]interface{} `json:"context,omitempty"` // Additional context
}

func parseErrAsDfnsInternalErr(err error) error {
	if err == nil {
		return nil
	}
	errValue := reflect.ValueOf(err)
	if errValue.Type().String() == "*dfnsapiclient.DfnsError" {
		var dfnsErr dfnsInternalError
		dfnsErr.raw = err.Error()
		if jErr := json.Unmarshal([]byte(err.Error()), &dfnsErr); jErr != nil {
			return errors.Wrapf(jErr, "dfns sdk compatibility issue: unable to parse dfnsapiclient.DfnsError with %v as json", err.Error())
		}
		return &dfnsErr
	}
	return nil
}
func (d *dfnsInternalError) Error() string {
	return d.raw
}

func passErrorInResponse(writer http.ResponseWriter, request *http.Request, err error) {
	if dfnsErr := parseErrAsDfnsInternalErr(err); dfnsErr != nil {
		var dfnsParsedErr *dfnsInternalError
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
