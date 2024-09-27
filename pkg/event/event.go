package event

import (
	"net/http"
	"time"

	"github.com/supergoodsystems/supergood-go/pkg/middleware"
)

// overridden in tests
var Clock = time.Now

func NewRequest(id string, r *http.Request) *Request {
	var body any
	body, r.Body = duplicateBody(r.Body)

	/*
		Note: When capturing via EBPF, URL is not successfully populated after response reassembly in func http.ReadRequest.
		sample capture:
			POST /post HTTP/1.1
			host: httpbin.org
			content-length: 12
			Connection: close
		http.ReadRequest parses the first line `POST /post HTTP/1.1` to retrieve RequestURI which does not contain the host
	*/
	url := r.URL.String()
	if url == "" {
		url = r.Host
	}

	req := &Request{
		ID:          id,
		Headers:     headersToMap(r.Header),
		Method:      r.Method,
		URL:         url,
		Path:        r.URL.Path,
		Search:      r.URL.RawQuery,
		Body:        body,
		RequestedAt: Clock(),
	}

	return req
}

func NewResponse(res *http.Response, err error) *Response {
	now := Clock()
	if err != nil {
		return &Response{
			Status:      0,
			StatusText:  "HTTP ERROR",
			Body:        err.Error(),
			RespondedAt: now,
		}
	}

	// Throwing an error on network failures causes duplicateBody to segfault on nil
	var body any
	if res.Body == nil {
		res.Body = http.NoBody
	} else {
		body, res.Body = duplicateBody(res.Body)
	}

	return &Response{
		Headers:     headersToMap(res.Header),
		Status:      res.StatusCode,
		StatusText:  res.Status,
		RespondedAt: now,
		Body:        body,
	}
}

func NewResponseFromMiddlewareObserver(r *middleware.ResponseObserver) *Response {
	now := Clock()
	return &Response{
		Headers:     r.Headers,
		Status:      r.Status,
		RespondedAt: now,
		Body:        r.Body,
	}
}
