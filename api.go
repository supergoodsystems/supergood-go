package supergood

import (
	"net/http"
	"sync"
	"time"
)

const FLUSH_INTERVAL = 10

/***
* This struct should mirror the backend API expected payloads interface
*
* EventRequestType {
*   request: RequestType;
*   response: ResponseType;
* }
*
* type BodyType = Record<string, string>;
*
* interface RequestType {
*   id: string;
*   headers: Headers;
*   method: string;
*   url: string;
*   path: string;
*   search: string;
*   body?: string | BodyType | [BodyType];
*   requestedAt: Date;
* }
*
* interface ResponseType {
*   headers: Headers;
*   status: number;
*   statusText: string;
*   body?: string | BodyType | [BodyType];
*   respondedAt: Date;
*   duration?: number;
* }
**/
type RequestResponse struct {
	URL      string
	duration time.Duration
}

type SupergoodTransport struct {
	transport    http.RoundTripper
	requestMutex sync.Mutex
	requests     []*RequestResponse
}

func (i *SupergoodTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := i.transport.RoundTrip(r)
	i.requestMutex.Lock()
	i.requests = append(i.requests, &RequestResponse{
		URL:      r.URL.String(),
		duration: time.Since(start),
	})
	defer i.requestMutex.Unlock()
	return resp, err
}

func (i *SupergoodTransport) GetCache() []*RequestResponse {
	return i.requests
}

type Interceptor interface {
	GetCache() []*RequestResponse
}

// Setup instruments the default client to log requests with the supergood API
func SetupClient(client *http.Client) Interceptor {
	transport := &SupergoodTransport{transport: client.Transport}
	client.Transport = transport
	return transport
}

// Setup instruments the default client to log requests with the supergood API
func GlobalInit() {
	http.DefaultTransport = &SupergoodTransport{transport: http.DefaultTransport, requests: make([]*RequestResponse, 0, 10)}
}
