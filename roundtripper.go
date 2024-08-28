package supergood

import (
	"fmt"
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
	shouldProxy := rt.sg.RemoteConfig.GetProxyEnabledForHost(req.URL.Host)

	if endpoint != nil {
		endpointId = endpoint.Id
		endpointAction = endpoint.Action
	}

	if !rt.shouldLogRequest(req, endpointAction) {
		if shouldProxy {
			rt.proxyRequest(req)
		}
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
		if shouldProxy {
			rt.proxyRequest(req)
		}
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

func (rt *roundTripper) proxyRequest(req *http.Request) {
	originalURLHost := req.URL.Host

	req.URL.Host = rt.sg.options.ProxyHost
	req.Host = rt.sg.options.ProxyHost

	req.Header.Add("X-Supergood-ClientID", rt.sg.options.ClientID)
	req.Header.Add("X-Supergood-ClientSecret", rt.sg.options.ClientSecret)
	req.Header.Add("X-Supergood-Upstream", fmt.Sprintf("https://%s", originalURLHost))
}
