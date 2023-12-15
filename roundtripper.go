package supergood

import (
	"net/http"

	uuid "github.com/satori/go.uuid"
	"github.com/supergoodsystems/supergood-go/internal/event"
)

type roundTripper struct {
	sg   *Service
	next http.RoundTripper
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	endpoint, errors := rt.sg.rc.MatchRequestAgainstEndpoints(req)
	for _, err := range errors {
		rt.sg.handleError(err)
	}

	endpointId := ""
	endpointAction := "Accept"
	if endpoint != nil {
		endpointId = endpoint.Id
		endpointAction = endpoint.Action
	}

	// Do not forward to supergood if the request is not in the list of user provided
	// selected requests OR if the request is ignored by the supergood remote config
	if !rt.sg.options.SelectRequests(req) || endpointAction == "Ignore" {
		return rt.next.RoundTrip(req)
	}

	id := uuid.NewV4().String()
	rt.sg.logRequest(id, event.NewRequest(id, req), endpointId)
	resp, err := rt.next.RoundTrip(req)
	rt.sg.logResponse(id, event.NewResponse(resp, err))

	return resp, err
}
