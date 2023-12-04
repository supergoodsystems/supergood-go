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

	// RecordRequestBody additionally sends the body of requests to supergood for debugging.
	// Defaults to false, if set true all values will be redacted and hashed unless specified
	RecordRequestBody bool

	// IncludeRequestBodyKeys is a list of keys who's value which to NOT redact in the request body
	// if RecordRequestBody is true
	// (defaults to an empty map)
	IncludeSpecifiedRequestBodyKeys map[string]bool

	// SkipRedaction allows content from an event payload to be passed to the supergood system for
	// finer grain anomoly detection
	SkipRedaction bool

	// RecordResponseBody additionally sends the body of responses to supergood for debugging.
	// Defaults to false, if set true all values will be redacted and hashed unless specified
	RecordResponseBody bool

	// IncludeResponseBodyKeys is a list of keys who's value which to NOT redact in the response body
	// if RecordResponseBody is true
	// (defaults to an empty map)
	IncludeSpecifiedResponseBodyKeys map[string]bool

	// Supergood replaces sensitive headers by the sha1 of their contents, by default.
	// IncludeSpecifiedRequestHeadersKeys will override this behavior and include the specified value
	// Matching is case insensitive.
	IncludeSpecifiedRequestHeaderKeys map[string]bool

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

	if o.IncludeSpecifiedRequestHeaderKeys == nil {
		o.IncludeSpecifiedRequestHeaderKeys = map[string]bool{}
	} else {
		for k, v := range o.IncludeSpecifiedRequestHeaderKeys {
			o.IncludeSpecifiedRequestHeaderKeys[strings.ToLower(k)] = v
		}
	}

	if o.IncludeSpecifiedRequestBodyKeys == nil {
		o.IncludeSpecifiedRequestBodyKeys = map[string]bool{}
	}

	if o.IncludeSpecifiedResponseBodyKeys == nil {
		o.IncludeSpecifiedResponseBodyKeys = map[string]bool{}
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
		o.FlushInterval = 10 * time.Second
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
