package supergood

import (
	"net/http"

	uuid "github.com/satori/go.uuid"
)

type roundTripper struct {
	sg   *Service
	next http.RoundTripper
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if !rt.sg.options.SelectRequests(req) {
		return rt.next.RoundTrip(req)
	}

	id := uuid.NewV4().String()
	rt.sg.logRequest(id, newRequest(id, req, rt.sg.options))
	resp, err := rt.next.RoundTrip(req)
	rt.sg.logResponse(id, newResponse(resp, err, rt.sg.options))
	return resp, err
}