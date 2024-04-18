package supergood

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/supergoodsystems/supergood-go/pkg/event"
)

type roundTripper struct {
	sg   *Service
	next http.RoundTripper
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	endpoint, errors := rt.sg.RemoteConfig.MatchRequestAgainstEndpoints(req)
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
	// selected requests OR if the request is ignored by the supergood remote config OR if
	// remote config is not initialized
	if !rt.shouldLogRequest(req, endpointAction) {
		return rt.next.RoundTrip(req)
	}

	id := uuid.New().String()
	logged := rt.sg.LogRequest(id, event.NewRequest(id, req), endpointId)

	var resp *http.Response
	var err error
	if endpointAction == "Block" {
		resp = &http.Response{
			Status:     "Blocked by Supergood: Too many requests",
			StatusCode: 429,
		}
	} else {
		resp, err = rt.next.RoundTrip(req)
	}

	if logged {
		rt.sg.LogResponse(id, event.NewResponse(resp, err))
	}

	return resp, err
}

func (rt *roundTripper) shouldLogRequest(req *http.Request, endpointAction string) bool {
	if !rt.sg.RemoteConfig.IsInitialized() {
		return false
	}

	allowed, err := rt.sg.options.isRequestInAllowedDomains(req)
	if err != nil {
		rt.sg.handleError(err)
	}
	if !allowed {
		return false
	}

	if endpointAction == "Ignore" {
		return false
	}

	if rt.sg.options.SelectRequests != nil {
		return rt.sg.options.SelectRequests(req)
	}

	return true
}
