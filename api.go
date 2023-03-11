package supergood

import (
	"fmt"
	"net/http"
	"sync"
)

const FLUSH_INTERVAL = 10

type Interceptor struct {
	transport    http.RoundTripper
	requestMutex sync.Mutex
	requests     []*http.Request
}

func (*Interceptor) logRequest(r *http.Request) {
	fmt.Println("Supergood Request:", r.Body)
}

func (*Interceptor) logResponse(r *http.Response) {
	fmt.Println("Supergood Response:", r.Body)
}

func (i *Interceptor) RoundTrip(r *http.Request) (*http.Response, error) {
	i.logRequest(r)
	resp, err := i.transport.RoundTrip(r)
	i.logResponse(resp)
	return resp, err
}

// Setup instruments the default client to log requests with the supergood API
func SetupClient(client *http.Client) {
	client.Transport = &Interceptor{transport: client.Transport}
}
