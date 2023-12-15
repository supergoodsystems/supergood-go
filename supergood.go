// package supergood provides support for logging API requests to [Supergood].
//
// You can use it globally by overriding [http.DefaultClient] with a supergood
// enabled version, or more selectively by wrapping specific clients in your
// codebase.
//
// [Supergood]: https://supergood.ai
package supergood

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/supergoodsystems/supergood-go/internal/event"
	"github.com/supergoodsystems/supergood-go/internal/redact"
	remoteconfig "github.com/supergoodsystems/supergood-go/internal/remote-config"
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

	close   chan chan error
	mutex   sync.Mutex
	options *Options
	queue   map[string]*event.Event
	rc      remoteconfig.RemoteConfig
}

// New creates a new supergood service.
// An error is returned only if the configuration is invalid.
func New(o *Options) (*Service, error) {
	o, err := o.parse()
	if err != nil {
		return nil, err
	}

	sg := &Service{
		options: o,
		close:   make(chan chan error),
	}

	client := http.DefaultClient
	if sg.options.HTTPClient != nil {
		client = sg.options.HTTPClient
	}
	sg.DefaultClient = sg.Wrap(client)

	// Comment: I'd like to have passed sg.options to a New() func
	// however that requires that the remote config package have a dependency on supergood.Options
	// which causes a circular dependency. I'd like to avoid moving supergood.Options to a separate package
	// since it's nicer for end users to initialize the supergood client with a single supergood import
	// e.g. supergood.New(&supergood.Options{}) instead of supergood.New(&supergoodOptions.Options{})
	sg.rc = remoteconfig.New(remoteconfig.RemoteConfigOpts{
		BaseURL:                 sg.options.BaseURL,
		ClientID:                sg.options.ClientID,
		ClientSecret:            sg.options.ClientSecret,
		Client:                  sg.options.HTTPClient,
		FetchInterval:           sg.options.RemoteConfigFetchInterval,
		HandleError:             sg.options.OnError,
		RedactRequestBodyKeys:   sg.options.RedactRequestBodyKeys,
		RedactResponseBodyKeys:  sg.options.RedactResponseBodyKeys,
		RedactRequestHeaderKeys: sg.options.RedactRequestHeaderKeys,
	})

	sg.reset()

	// TODO: dont error on remote config initalization
	// Do not send events unless we've successfully fetched remote config
	err = sg.rc.Init()
	if err != nil {
		return nil, err
	}

	go sg.loop()
	go sg.rc.Refresh()
	return sg, nil
}

// Wrap returns a new http client that calls the original and
// also sends data to supergood.
func (sg *Service) Wrap(client *http.Client) *http.Client {
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	return &http.Client{
		Transport:     &roundTripper{sg: sg, next: next},
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       client.Timeout,
	}
}

// Close sends any pending requests to supergood
// and shuts down the service.
func (sg *Service) Close() error {
	ch := make(chan error)
	sg.close <- ch
	close(sg.close)
	sg.rc.Close()
	return <-ch
}

func (sg *Service) logRequest(id string, req *event.Request, endpointId string) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.queue[id] = &event.Event{Request: req, MetaData: event.MetaData{EndpointId: endpointId}}
}

func (sg *Service) logResponse(id string, resp *event.Response) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	if entry, ok := sg.queue[id]; ok {
		entry.Response = resp
		entry.Response.Duration = int(entry.Response.RespondedAt.Sub(entry.Request.RequestedAt) / time.Millisecond)
	}
}

func (sg *Service) loop() {
	var closed chan error
	for {
		select {
		case closed = <-sg.close:
			err := sg.flush(true)
			if err != nil {
				sg.handleError(err)
			}
			closed <- err
			return
		case <-time.After(sg.options.FlushInterval):
			err := sg.flush(false)
			if err != nil {
				sg.handleError(err)
			}
		}
	}
}

func (sg *Service) flush(force bool) error {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()

	toSend := []*event.Event{}
	for key, entry := range sg.queue {
		if entry.Response == nil && !force {
			continue
		}
		delete(sg.queue, key)
		toSend = append(toSend, entry)
		errs := redact.Redact(toSend, &sg.rc)
		for _, err := range errs {
			sg.handleError(err)
		}
	}

	if len(toSend) == 0 {
		return nil
	}
	return sg.post("/events", toSend)
}

func (sg *Service) reset() map[string]*event.Event {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()

	entries := sg.queue
	sg.queue = map[string]*event.Event{}
	return entries
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

func getVersion() packageVersion {
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/supergoodsystems/supergood-go" {
				return packageVersion{Name: "supergood-go", Version: dep.Version}
			}
		}
	}
	return packageVersion{Name: "supergood-go", Version: "unknown"}
}

func (sg *Service) logError(e error) error {
	if strings.Contains(e.Error(), "invalid ClientID") {
		return nil
	}

	// TODO: we don't currently include the data or the config
	return sg.post("/errors", &errorReport{
		Error:   e.Error(),
		Message: e.Error(),
		Payload: getVersion(),
	})
}

func (sg *Service) post(path string, body any) error {
	url, err := url.JoinPath(sg.options.BaseURL, path)
	if err != nil { // should not happen as checked in New()
		return err
	}

	serialized, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(serialized))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(sg.options.ClientID+":"+sg.options.ClientSecret)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := sg.options.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("supergood: invalid ClientID or ClientSecret")
	} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("supergood: got HTTP %v posting to %v", resp.Status, path)
	}

	return nil
}

func (sg *Service) handleError(err error) {
	sg.options.OnError(err)
	if err2 := sg.logError(err); err2 != nil {
		sg.options.OnError(err2)
	}
}
