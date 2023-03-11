package supergood

import (
	"fmt"
	"net/http"
)

type Interceptor struct {
	core http.RoundTripper
}

func (Interceptor) logRequest(r *http.Request) {
	fmt.Println("Supergood Request:", r.Body)
}

func (Interceptor) logResponse(r *http.Response) {
	fmt.Println("Supergood Response:", r.Body)
}

func (i Interceptor) RoundTrip(r *http.Request) (*http.Response, error) {
	i.logRequest(r)
	resp, err := i.core.RoundTrip(r)
	i.logResponse(resp)
	return resp, err
}

// Setup instruments the default client to log requests with the supergood API
func Setup() {
	// responseCache := cache.New(cache.NoExpiration, cache.NoExpiration)
	// requestCache := cache.New(cache.NoExpiration, cache.NoExpiration)
	http.DefaultClient = &http.Client{
		Transport: Interceptor{http.DefaultTransport},
	}
}
