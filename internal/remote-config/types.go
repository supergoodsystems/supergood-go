package remoteconfig

import (
	"net/http"
	"regexp"
	"sync"
	"time"
)

type RemoteConfigOpts struct {
	BaseURL                 string
	ClientID                string
	ClientSecret            string
	Client                  *http.Client
	FetchInterval           time.Duration
	HandleError             func(error)
	RedactRequestBodyKeys   map[string][]string
	RedactResponseBodyKeys  map[string][]string
	RedactRequestHeaderKeys map[string][]string
}

type RemoteConfig struct {
	baseURL                 string
	cache                   map[string]map[string]EndpointCacheVal
	clientID                string
	clientSecret            string
	client                  *http.Client
	close                   chan struct{}
	fetchInterval           time.Duration
	handleError             func(error)
	mutex                   sync.RWMutex
	redactRequestBodyKeys   map[string][]string
	redactResponseBodyKeys  map[string][]string
	redactRequestHeaderKeys map[string][]string
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
	Id            string
	Regex         regexp.Regexp
	Location      string
	Action        string
	SensitiveKeys []SensitiveKeys
}
