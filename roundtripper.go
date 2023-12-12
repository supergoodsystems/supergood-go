package supergood

import (
	"net/http"

	uuid "github.com/satori/go.uuid"
	"github.com/supergoodsystems/supergood-go/internal/event"
	"github.com/supergoodsystems/supergood-go/internal/ignore"
)

type roundTripper struct {
	sg   *Service
	next http.RoundTripper
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	shouldIgnore, errors := ignore.ShouldIgnoreRequest(req, &rt.sg.rc)
	for _, err := range errors {
		rt.sg.handleError(err)
	}
	if !rt.sg.options.SelectRequests(req) || shouldIgnore {
		return rt.next.RoundTrip(req)
	}

	id := uuid.NewV4().String()
	rt.sg.logRequest(id, event.NewRequest(id, req))
	resp, err := rt.next.RoundTrip(req)
	rt.sg.logResponse(id, event.NewResponse(resp, err))
	return resp, err
}
