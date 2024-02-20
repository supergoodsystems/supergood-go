package supergood

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Options configure the Supergood service
type Options struct {
	// ClientID can be found on https://dashboard.supergood.ai/api-keys.
	// (defaults to the SUPERGOOD_CLIENT_ID environment variable)
	ClientID string
	// ClientID can be found on https://dashboard.supergood.ai/api-keys.
	// (defaults to the SUPERGOOD_CLIENT_SECRET environment variable)
	ClientSecret string
	// BaseURL is where to find the supergood API
	// (defaults to the SUPERGOOD_BASE_URL environment variable,
	// or "https://api.supergood.ai" if not set)
	BaseURL string

	// RedactRequestBodyKeys is a map of top level domains to a list of keys within
	// the request body representing object paths to be redacted.
	// map[string][]string {"plaid.com": []string{"path.to.redacted.[].field"}}
	RedactRequestBodyKeys map[string][]string

	// RedactResponseBodyKeys is a map of top level domains to a list of keys within
	// the response body representing object paths to be redacted.
	// map[string][]string {"plaid.com": []string{"path.to.redacted.[].field"}}
	RedactResponseBodyKeys map[string][]string

	// RedactRequestHeaderKeys is a map of top level domains to a list of keys within
	// the request headers representing keys to be redacted.
	// map[string][string] {"plaid.com": []string{"client-id", "client-secret"}}
	RedactRequestHeaderKeys map[string][]string

	// List of strings to match against the host of the request URL in order to determine
	// whether or not to log the request to supergood, based on the domain. Case sensitive.
	// (by default all domains are logged)
	AllowedDomains []string

	// SelectRequests selects which requests are logged to supergood.
	// Return true to log the request to supergood.
	// Overrides `AllowedDomains`
	// (by default all requests are logged)
	SelectRequests func(r *http.Request) bool

	// FlushInterval configures how frequently supergood sends batches of
	// logs to the API. (defaults to 1 * time.Second)
	FlushInterval time.Duration

	// OnError allows you to handle errors uploading events to supergood
	// (by default errors are logged to os.Stderr)
	OnError func(error)

	// The HTTPClient to use to make requests to Supergood's API
	// (defaults to http.DefaultClient)
	HTTPClient *http.Client

	// Log Level to use for logging, debug will print flushes
	LogLevel string

	// RemoteConfigFetchInterval configures how frequently supergood retrieves
	// the remote config which is used to ignore / accept traffic from client endpoints
	// as well as mask sensitive keys
	RemoteConfigFetchInterval time.Duration

	// ServiceName is an optional parameter that can be passed that helps differentiate
	// services that use the same supergood api-key
	ServiceName string

	// DisableDefaultWrappedClient prevents the go client from wrapping an HTTP client by default.
	// This functionality will be used by other packages that might want to leverage some of this go packages functionality
	// without having to intercept traffic via Roundtripper
	DisableDefaultWrappedClient bool
}

func (o *Options) parse() (*Options, error) {
	if o == nil {
		o = &Options{}
	} else {
		copy := *o
		o = &copy
	}

	if o.ClientID == "" {
		o.ClientID = os.Getenv("SUPERGOOD_CLIENT_ID")
	}
	if o.ClientID == "" {
		return nil, fmt.Errorf("supergood: missing ClientID (SUPERGOOD_CLIENT_ID not in environment)")
	}

	if o.ClientSecret == "" {
		o.ClientSecret = os.Getenv("SUPERGOOD_CLIENT_SECRET")
	}
	if o.ClientSecret == "" {
		return nil, fmt.Errorf("supergood: missing ClientSecret (SUPERGOOD_CLIENT_SECRET not in environment)")
	}

	if o.BaseURL == "" {
		o.BaseURL = os.Getenv("SUPERGOOD_BASE_URL")
	}
	if o.BaseURL == "" {
		o.BaseURL = "https://api.supergood.ai"
	}
	if u, err := url.Parse(o.BaseURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("supergood: invalid BaseURL: %w", err)
	}

	if o.FlushInterval == 0 {
		o.FlushInterval = time.Second
	}
	if o.FlushInterval < time.Millisecond {
		return nil, fmt.Errorf("supergood: FlushInterval too small, did you forget to multiply by time.Second?")
	}

	if o.HTTPClient == nil {
		o.HTTPClient = http.DefaultClient
	}

	if o.OnError == nil {
		o.OnError = func(e error) {
			fmt.Fprintln(os.Stderr, e)
		}
	}

	if o.RedactRequestHeaderKeys == nil {
		o.RedactRequestHeaderKeys = map[string][]string{}
	} else {
		for k, v := range o.RedactRequestHeaderKeys {
			o.RedactRequestHeaderKeys[strings.ToLower(k)] = v
		}
	}

	if o.RedactRequestBodyKeys == nil {
		o.RedactRequestBodyKeys = map[string][]string{}
	} else {
		for k, v := range o.RedactRequestBodyKeys {
			o.RedactRequestBodyKeys[strings.ToLower(k)] = v
		}
	}

	if o.RedactResponseBodyKeys == nil {
		o.RedactResponseBodyKeys = map[string][]string{}
	} else {
		for k, v := range o.RedactResponseBodyKeys {
			o.RedactResponseBodyKeys[strings.ToLower(k)] = v
		}
	}

	if o.AllowedDomains != nil && len(o.AllowedDomains) > 0 {
		if contains(o.BaseURL, o.AllowedDomains) {
			return nil, fmt.Errorf("supergood: AllowedDomain can not match BaseURL")
		}

	}

	if o.SelectRequests == nil {
		url, err := url.Parse(o.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("supergood: invalid BaseURL: %w", err)
		}

		baseUrlHostName := strings.TrimPrefix(url.Host, "www.")

		if o.AllowedDomains != nil && len(o.AllowedDomains) > 0 {
			o.SelectRequests = func(r *http.Request) bool {
				if r != nil {
					return r.URL.Host != baseUrlHostName && contains(r.URL.Host, o.AllowedDomains)
				}
				return true
			}
		} else {
			// Do not log API calls to supergood
			o.SelectRequests = func(r *http.Request) bool {
				if r != nil {
					return r.URL.Host != baseUrlHostName
				}
				return true
			}
		}
	}

	if o.RemoteConfigFetchInterval == 0 {
		o.RemoteConfigFetchInterval = 10 * time.Second
	}
	if o.RemoteConfigFetchInterval < time.Millisecond {
		return nil, fmt.Errorf("supergood: RemoteConfigFetchInterval too small, did you forget to multiply by time.Second?")
	}

	return o, nil
}

// Function to determine if a target string contains any value from an array of strings
func contains(target string, values []string) bool {
	for _, value := range values {
		if strings.Contains(target, value) {
			return true
		}
	}
	return false
}
