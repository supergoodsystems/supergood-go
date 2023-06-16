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
	// or "https://dashboard.supergood.ai" if not set)
	BaseURL string

	// RecordRequestBody additionally sends the body of requests to supergood for debugging.
	// (defaults to false)
	RecordRequestBody bool
	// RecordResponseBody additionally sends the body of responses to supergood for debugging.
	// (defaults to false)
	RecordResponseBody bool
	// RedactHeaders replaces sensitive headers by the sha1 of their contents.
	// Matching is case insensitive.
	// (defaults to redacting "Authorization", "Cookie" and "Set-Cookie")
	RedactHeaders map[string]bool
	// SelectRequests selects which requests are logged to supergood.
	// Return true to log the request to supergood.
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
		o.BaseURL = "https://dashboard.supergood.ai"
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

	headers := o.RedactHeaders
	if headers == nil {
		headers = map[string]bool{
			"Authorization": true,
			"Cookie":        true,
			"Set-Cookie":    true,
		}
	}
	o.RedactHeaders = map[string]bool{}
	for k, v := range headers {
		o.RedactHeaders[strings.ToLower(k)] = v
	}

	if o.SelectRequests == nil {
		o.SelectRequests = func(r *http.Request) bool { return true }
	}

	return o, nil
}
