package supergood

import (
	"net/http"
	"sync"

	"github.com/supergoodsystems/supergood-go/pkg/event"
	remoteconfig "github.com/supergoodsystems/supergood-go/pkg/remote-config"
)

// Service collates request logs and uploads them to the Supergood API
// in batches.
//
// As request logs are batched locally, you must call [Service.Close]
// before your program exits to upload any pending logs.
type Service struct {
	// DefaultClient is a wrapped version of http.DefaultClient
	// If you'd like to use supergood on all requests, set
	// http.DefaultClient = sg.DefaultClient.

	DefaultClient *http.Client

	close        chan chan error
	mutex        sync.Mutex
	options      *Options
	queue        map[string]*event.Event
	RemoteConfig remoteconfig.RemoteConfig
}

type errorReport struct {
	Error   string         `json:"error"`
	Message string         `json:"message"`
	Payload packageVersion `json:"payload"`
}

type packageVersion struct {
	Name    string `json:"packageName"`
	Version string `json:"packageVersion"`
}

type telemetry struct {
	CacheKeyCount int    `json:"cacheKeyCount"`
	ServiceName   string `json:"serviceName"`
}
