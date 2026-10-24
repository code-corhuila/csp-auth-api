package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

// maxBodyBytes is the explicit limit of the request body (Norma 5.3.10).
const maxBodyBytes = 1 << 20

// decodeBody reads the JSON body into a T within the size limit. Unknown properties are ignored,
// so the contract can grow with optional fields without breaking clients (API guidelines).
// It returns the problems that prevented reading the body, if any.
func decodeBody[T any](w http.ResponseWriter, r *http.Request) (T, []fieldError) {
	return decodeBodyWithin[T](w, r, maxBodyBytes)
}

// decodeBodyWithin is decodeBody with the limit of the route, for the routes whose contract sets a smaller one.
func decodeBodyWithin[T any](w http.ResponseWriter, r *http.Request, limit int64) (T, []fieldError) {
	var body T
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return body, []fieldError{{Field: "Content-Type", Message: "must be application/json"}}
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	err := decoder.Decode(&body)
	if err == nil {
		if _, trailing := decoder.Token(); trailing != io.EOF {
			err = errors.New("unexpected data after the JSON value")
		}
	}
	if err == nil {
		return body, nil
	}
	var tooLarge *http.MaxBytesError
	var wrongType *json.UnmarshalTypeError
	switch {
	case errors.As(err, &tooLarge):
		return body, []fieldError{{Field: "body", Message: fmt.Sprintf("must be at most %d bytes", limit)}}
	case errors.As(err, &wrongType):
		return body, []fieldError{{Field: wrongType.Field, Message: "must be a " + wrongType.Type.String()}}
	default:
		return body, []fieldError{{Field: "body", Message: "must be a valid JSON object"}}
	}
}
