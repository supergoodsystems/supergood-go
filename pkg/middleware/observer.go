package middleware

import (
	"encoding/json"
	"net/http"
	"unicode/utf8"
)

type ResponseObserver struct {
	http.ResponseWriter
	Status      int
	Body        any
	Headers     map[string]string
	wroteHeader bool
}

func (o *ResponseObserver) Write(p []byte) (n int, err error) {
	if !o.wroteHeader {
		o.WriteHeader(http.StatusOK)
	}
	n, err = o.ResponseWriter.Write(p)
	o.Body = duplicteBodyFromBytes(p)
	return
}

func (o *ResponseObserver) WriteHeader(code int) {
	o.ResponseWriter.WriteHeader(code)
	if o.wroteHeader {
		return
	}
	o.wroteHeader = true
	o.Status = code
}

func duplicteBodyFromBytes(b []byte) (body any) {
	if !utf8.Valid(b) {
		body = &b
	} else {
		body = map[string]any{}
		if err := json.Unmarshal(b, &body); err != nil {
			body = string(b)
		}
	}
	return
}
