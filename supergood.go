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

	options *Options
	mutex   sync.Mutex
	queue   map[string]*event
	close   chan chan error
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

	sg.DefaultClient = sg.Wrap(http.DefaultClient)

	sg.reset()
	go sg.loop()
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
	return <-ch
}

func (sg *Service) logRequest(id string, req *request) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.queue[id] = &event{Request: req}
}

func (sg *Service) logResponse(id string, resp *response) {
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
				if err2 := sg.logError(err); err2 != nil {
					sg.options.OnError(err2)
				}
			}
			closed <- err
			return
		case <-time.After(sg.options.FlushInterval):
			if err := sg.flush(false); err != nil {
				sg.options.OnError(err)
				if err2 := sg.logError(err); err2 != nil {
					sg.options.OnError(err2)
				}
			}
		}
	}
}

func (sg *Service) flush(force bool) error {
	entries := sg.reset()
	toSend := []*event{}

	for _, entry := range entries {
		if entry.Response == nil && !force {
			continue
		}
		toSend = append(toSend, entry)
	}

	if len(toSend) == 0 {
		return nil
	}
	return sg.post("/api/events", toSend)
}

func (sg *Service) reset() map[string]*event {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()

	entries := sg.queue
	sg.queue = map[string]*event{}

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
	return sg.post("/api/errors", &errorReport{
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
