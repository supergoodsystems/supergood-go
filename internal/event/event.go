package event

import (
	"net/http"
	"time"
)

// overridden in tests
var clock = time.Now

func NewRequest(id string, r *http.Request) *Request {
	var body any
	body, r.Body = duplicateBody(r.Body)

	req := &Request{
		ID:          id,
		Headers:     headersToMap(r.Header),
		Method:      r.Method,
		URL:         r.URL.String(),
		Path:        r.URL.Path,
		Search:      r.URL.RawQuery,
		Body:        body,
		RequestedAt: clock(),
	}

	return req
}

func NewResponse(res *http.Response, err error) *Response {
	now := clock()
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
