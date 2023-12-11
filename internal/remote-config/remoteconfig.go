package remoteconfig

import (
	"time"
)

// Init initializes the remote config cache
func (rc *RemoteConfig) Init() error {
	return rc.fetchAndSetConfig()
}

// RefreshRemoteConfig refreshes the remote config on an interval
// and receives a close channel to gracefully return on application exit
func (rc *RemoteConfig) Refresh() {
	for {
		select {
		case <-rc.Close:
			return
		case <-time.After(rc.FetchInterval):
			if err := rc.fetchAndSetConfig(); err != nil {
				rc.HandleError(err)
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

	return rc.Create(resp)
}
