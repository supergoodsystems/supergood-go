package remoteconfig

import (
	"net/http"
	"regexp"
	"sync"
	"time"
)

type RemoteConfig struct {
	BaseURL                 string
	Cache                   map[string][]EndpointCacheVal
	ClientID                string
	ClientSecret            string
	Client                  *http.Client
	Close                   chan struct{}
	FetchInterval           time.Duration
	HandleError             func(error)
	Mutex                   sync.RWMutex
	RedactRequestBodyKeys   map[string][]string
	RedactResponseBodyKeys  map[string][]string
	RedactRequestHeaderKeys map[string][]string
}

type RemoteConfigResponse struct {
	Id        string     `json:"id"`
	Domain    string     `json:"domain"`
	Name      string     `json:"name"`
	Endpoints []Endpoint `json:"endpoints"`
}

type Endpoint struct {
	Id                    string                `json:"id"`
	Name                  string                `json:"name"`
	MatchingRegex         MatchingRegex         `json:"matchingRegex"`
	EndpointConfiguration EndpointConfiguration `json:"endpointConfiguration"`
}

type MatchingRegex struct {
	Location string `json:"location"`
	Regex    string `json:"regex"`
}

type EndpointConfiguration struct {
	Id            string          `json:"id"`
	Acknowledged  bool            `json:"acknowledged"`
	Action        string          `json:"action"`
	UpdatedAt     time.Time       `json:"updatedAt"`
	SensitiveKeys []SensitiveKeys `json:"sensitiveKeys"`
}

type SensitiveKeys struct {
	Id        string    `json:"id"`
	KeyPath   string    `json:"keyPath"`
	Action    string    `json:"action"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type EndpointCacheVal struct {
	Regex         regexp.Regexp
	Location      string
	Action        string
	SensitiveKeys []SensitiveKeys
}

const (
	RequestHeadersStr  = "requestHeaders"
	RequestBodyStr     = "requestBody"
	ResponseHeadersStr = "responseHeaders"
	ResponseBodyStr    = "responseBody"
)
