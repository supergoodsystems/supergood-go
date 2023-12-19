package remoteconfig

import (
	"time"
)

// New creates a new RemoteConfig struct
func New(opts RemoteConfigOpts) RemoteConfig {
	return RemoteConfig{
		baseURL:                 opts.BaseURL,
		cache:                   map[string]map[string]EndpointCacheVal{},
		clientID:                opts.ClientID,
		clientSecret:            opts.ClientSecret,
		client:                  opts.Client,
		close:                   make(chan struct{}),
		fetchInterval:           opts.FetchInterval,
		initialized:             false,
		handleError:             opts.HandleError,
		redactRequestBodyKeys:   opts.RedactRequestBodyKeys,
		redactResponseBodyKeys:  opts.RedactResponseBodyKeys,
		redactRequestHeaderKeys: opts.RedactRequestHeaderKeys,
	}
}

// Init initializes the remote config cache
// Does not return an error - do not want to prevent client app from starting
// due to a failed config fetch from supergood
func (rc *RemoteConfig) Init() {
	err := rc.fetchAndSetConfig()
	if err != nil {
		rc.handleError(err)
	}
}

// RefreshRemoteConfig refreshes the remote config on an interval
// and receives a close channel to gracefully return on application exit
func (rc *RemoteConfig) Refresh() {
	for {
		select {
		case <-rc.close:
			return
		case <-time.After(rc.fetchInterval):
			if err := rc.fetchAndSetConfig(); err != nil {
				rc.handleError(err)
			}
		}
	}
}

// fetchAndSetConfig fetches the remote config from the supergood /config endpoint
// and then sets it in the Cache on the RemoteConfig
func (rc *RemoteConfig) fetchAndSetConfig() error {
	resp, err := rc.fetch()
	if err != nil {
		return err
	}

	err = rc.Create(resp)
	if err != nil {
		rc.initialized = true
	}

	return err
}
