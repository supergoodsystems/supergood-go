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
	RedactAll               bool
	RedactRequestBodyKeys   map[string][]string
	RedactResponseBodyKeys  map[string][]string
	RedactRequestHeaderKeys map[string][]string
}

type RemoteConfig struct {
	baseURL                 string
	cache                   map[string]map[string]EndpointCacheVal
	proxyCache              map[string]*ProxyEnabled
	clientID                string
	clientSecret            string
	client                  *http.Client
	close                   chan struct{}
	fetchInterval           time.Duration
	initialized             bool
	handleError             func(error)
	mutex                   sync.RWMutex
	proxyMutex              sync.RWMutex
	redactAll               bool
	redactRequestBodyKeys   map[string][]string
	redactResponseBodyKeys  map[string][]string
	redactRequestHeaderKeys map[string][]string
}

type RemoteConfigResponse struct {
	EndpointConfig []EndpointConfig `json:"endpointConfig"`
	ProxyConfig    ProxyConfig      `json:"proxyConfig"`
}

type ProxyConfig struct {
	VendorCredentialConfig map[string]ProxyEnabled `json:"vendorCredentialConfig"`
}
type ProxyEnabled struct {
	Enabled bool `json:"enabled"`
}
type EndpointConfig struct {
	Domain    string     `json:"domain"`
	Endpoints []Endpoint `json:"endpoints"`
}

type Endpoint struct {
	Id                    string                `json:"id"`
	Name                  string                `json:"name"`
	Method                string                `json:"method"`
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
	Method        string
	Location      string
	Action        string
	SensitiveKeys []SensitiveKeys
}
