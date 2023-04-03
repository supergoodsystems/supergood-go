package supergood

import (
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

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

type SupergoodError struct {
	payload map[string]string
	message string
	err     string
}

type Response struct {
	headers     string // JSON?
	status      int
	statusText  string
	body        string
	respondedAt time.Time
	duration    time.Duration
}

type Request struct {
	id          string
	headers     string // JSON?
	method      string
	url         string
	path        string
	search      string
	body        string //JSON?
	requestedAt time.Time
}

type RequestResponse struct {
	request  Request
	response Response
}

type SupergoodInterceptor struct {
	transport                  http.RoundTripper
	requestMutex               sync.Mutex
	responseMutex              sync.Mutex
	requests                   map[string]*Request
	responses                  map[string]*RequestResponse
	api                        *SupergoodApi
	config                     *SupergoodConfig
	ticker                     *time.Ticker
	waitGroup                  sync.WaitGroup
	numberOfConcurrentRequests int
}

type SupergoodConfig struct {
	KeysToHash        []string `json:"keysToHash"`
	FlushInterval     int      `json:"flushInterval"`
	CacheTtl          int      `json:"cacheTtl"`
	EventSinkEndpoint string   `json:"eventSinkEndpoint"`
	ErrorSinkEndpoint string   `json:"errorSinkEndpoint"`
	IgnoredDomains    []string `json:"ignoredDomains"`
}

func (i *SupergoodInterceptor) RoundTrip(req *http.Request) (*http.Response, error) {
	requestId := uuid.NewString()
	start := time.Now()

	// waitGroup will let me handle cleanup
	// nicely when the script exits or Interceptor.Close()
	// is called

	i.numberOfConcurrentRequests += 1
	i.waitGroup.Add(i.numberOfConcurrentRequests)
	go func() {
		defer i.waitGroup.Done()
		i.CacheRequest(req, requestId, start)
		i.numberOfConcurrentRequests -= 1
	}()

	// TODO: Replace with ReadCloser patch
	resp, err := i.transport.RoundTrip(req)

	i.numberOfConcurrentRequests += 1
	i.waitGroup.Add(i.numberOfConcurrentRequests)
	go func() {
		defer i.waitGroup.Done()
		i.CacheResponse(resp, requestId, start)
		i.numberOfConcurrentRequests -= 1
	}()

	return resp, err
}

func (i *SupergoodInterceptor) CacheRequest(req *http.Request, requestId string, start time.Time) {
	i.requestMutex.Lock()
	defer i.requestMutex.Unlock()

	i.requests[requestId] = &Request{
		id:          requestId,
		headers:     "{}",
		url:         req.URL.String(),
		path:        req.URL.Path,
		search:      req.URL.RawQuery,
		method:      req.Method,
		requestedAt: start,
		body:        "{}",
	}
}

func (i *SupergoodInterceptor) CacheResponse(resp *http.Response, requestId string, start time.Time) {
	i.responseMutex.Lock()
	defer i.responseMutex.Unlock()

	i.responses[requestId] = &RequestResponse{
		request: *i.requests[requestId],
		response: Response{
			headers:     "{}",
			status:      resp.StatusCode,
			statusText:  resp.Status,
			respondedAt: time.Now(),
			duration:    time.Now().Sub(start),
			body:        "{}",
		},
	}

	i.requestMutex.Lock()
	defer i.requestMutex.Unlock()

	delete(i.requests, requestId)

}

func (i *SupergoodInterceptor) FlushCache(force bool) []RequestResponse {

	// If cache is empty, do not flush
	if !force && len(i.responses) == 0 {
		return []RequestResponse{}
	}

	if force && len(i.requests) == 0 && len(i.responses) == 0 {
		return []RequestResponse{}
	}

	responses := []RequestResponse{}
	for _, value := range i.responses {
		responses = append(responses, *value)
	}

	if force {
		for _, value := range i.requests {
			responses = append(responses, RequestResponse{
				request:  *value,
				response: Response{},
			})
		}
	}

	// Add error handling here
	i.api.PostEvents(responses)

	i.responseMutex.Lock()
	defer i.responseMutex.Unlock()

	for key := range i.responses {
		delete(i.responses, key)
	}
	if force {
		i.requestMutex.Lock()
		defer i.requestMutex.Unlock()

		for key := range i.requests {
			delete(i.requests, key)
		}
	}
	return responses
}

func (i *SupergoodInterceptor) Close() []RequestResponse {
	i.waitGroup.Wait()
	responses := i.FlushCache(true)
	i.ticker.Stop()
	return responses
}

type Interceptor interface {
	CacheRequest(req *http.Request, requestId string, start time.Time)
	CacheResponse(resp *http.Response, requestId string, start time.Time)
	FlushCache(force bool) []RequestResponse
	Close() []RequestResponse
}

// Enable users to manually specify the http client
// instead of assuming the default one was used

func Init() Interceptor {
	// TODO: Figure out the difference between http.Client.transport and
	// http.defaultTransport
	// Do I need to patch both?
	httpClient := http.DefaultClient
	return InitWithClient(httpClient)
}

// TODO: Optional variatic parameters
func InitWithClient(httpClient *http.Client) Interceptor {

	godotenv.Load()
	clientId := os.Getenv("SUPERGOOD_CLIENT_ID")
	clientSecret := os.Getenv("SUPERGOOD_CLIENT_SECRET")
	baseUrl := os.Getenv("SUPERGOOD_BASE_URL")

	// Set up API from env vars
	api := &SupergoodApi{
		baseUrl: baseUrl,
	}
	api.SetAuthorizationString(clientId, clientSecret)

	// Fetch config from remote server
	config := api.FetchConfig()
	ticker := time.NewTicker(time.Duration(config.FlushInterval) * time.Second)

	interceptor := &SupergoodInterceptor{
		transport: http.DefaultTransport,
		requests:  make(map[string]*Request),
		responses: make(map[string]*RequestResponse),
		config:    config,
		ticker:    ticker,
		api:       api,
	}

	httpClient.Transport = interceptor

	// Flush cache at interval
	go func() {
		for {
			select {
			case <-ticker.C:
				interceptor.FlushCache(false)
			}
		}
	}()

	return interceptor
}

/*
1. Figure out how to post to the API.
2. Add go routine to flush on timer
3. Flush if number of entries exceeds certain count
4. Add ReadCloser wrappping
5. Add async config fetch.
*/
