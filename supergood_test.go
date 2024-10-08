package supergood

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supergoodsystems/supergood-go/pkg/event"
	remoteconfig "github.com/supergoodsystems/supergood-go/pkg/remote-config"
)

var events []*event.Event
var errorReports []*errorReport
var broken bool
var twiceBroken bool
var remoteConfigBroken bool

func reset() {
	events = []*event.Event{}
	errorReports = []*errorReport{}
}

var clientID = "test_client_id"
var clientSecret = "test_client_secret"

type mockRoundTripper struct {
	DefaultClient     *http.Client
	mockServerChannel chan int
}

func (mrt *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	go func() {
		mrt.mockServerChannel <- 1
	}()
	return http.DefaultTransport.RoundTrip(req)
}

// mock client to test wrapped client behavior
func mockWrapClient(client *http.Client, ch chan int) *http.Client {
	client.Transport = &mockRoundTripper{
		DefaultClient:     client,
		mockServerChannel: ch,
	}
	return client
}

// boot up a server on an unused local port and return
// http://localhost:<port>
func mockServer(t *testing.T, h http.HandlerFunc) string {
	listener, err := net.Listen("tcp", "localhost:")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
	})

	go http.Serve(listener, h)
	return "http://" + listener.Addr().String()
}

// mock api.supergood.ai for testing
func mockApiServer(t *testing.T) string {

	return mockServer(t, func(rw http.ResponseWriter, r *http.Request) {

		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret)) {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}

		if r.Header.Get("Content-Type") != "application/json" {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte(`{"status":"BadRequest"}`))
			return
		}

		if twiceBroken && (r.URL.Path != "/v2/config") {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte(`Oops`))
			return
		}

		if broken && (r.URL.Path != "/v2/config") {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte(`Oops`))
			return
		}

		if r.URL.Path == "/events" && r.Method == "POST" {
			newEvents := []*event.Event{}
			err := json.NewDecoder(r.Body).Decode(&newEvents)
			require.NoError(t, err)
			events = append(events, newEvents...)

			rw.Write([]byte(`{"message":"Success"}`))
			return
		}

		if r.URL.Path == "/v2/config" && r.Method == "GET" && !remoteConfigBroken {
			remoteConfig := remoteconfig.RemoteConfigResponse{
				EndpointConfig: []remoteconfig.EndpointConfig{
					{
						Domain: "ignored-domain.com",
						Endpoints: []remoteconfig.Endpoint{
							{
								Id:     "test-endpoint-id",
								Name:   "ignore me endpoint",
								Method: "GET",
								MatchingRegex: remoteconfig.MatchingRegex{
									Location: "path",
									Regex:    "/ignore-me",
								},
								EndpointConfiguration: remoteconfig.EndpointConfiguration{
									Action: "Ignore",
								},
							},
						},
					},
					{
						Domain: "blocked-domain.com",
						Endpoints: []remoteconfig.Endpoint{
							{
								Id:     "test-endpoint-id",
								Name:   "block me endpoint",
								Method: "GET",
								MatchingRegex: remoteconfig.MatchingRegex{
									Location: "path",
									Regex:    "/block-me",
								},
								EndpointConfiguration: remoteconfig.EndpointConfiguration{
									Action: "Block",
								},
							},
						},
					},
					{
						Domain: "supergood-testbed.herokuapp.com",
					},
					{
						Domain: "httpbin.org",
					},
				},
				ProxyConfig: remoteconfig.ProxyConfig{
					VendorCredentialConfig: map[string]remoteconfig.ProxyEnabled{
						"api.openai.com": {Enabled: true},
					},
				},
			}
			bytes, _ := json.Marshal(remoteConfig)
			rw.Write(bytes)
			return
		}

		rw.WriteHeader(http.StatusNotFound)
		rw.Write([]byte(`{"status":"NotFound"}`))
	})
}

// mock telemetry.supergood.ai for testing
func mockTelemetryServer(t *testing.T) string {

	return mockServer(t, func(rw http.ResponseWriter, r *http.Request) {

		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret)) {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}

		if r.Header.Get("Content-Type") != "application/json" {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte(`{"status":"BadRequest"}`))
			return
		}

		if r.URL.Path == "/telemetry" {
			rw.Write([]byte(`{"message":"Success"}`))
			return
		}

		if r.URL.Path == "/errors" {
			newErr := &errorReport{}
			err := json.NewDecoder(r.Body).Decode(&newErr)
			require.NoError(t, err)
			errorReports = append(errorReports, newErr)

			rw.Write([]byte(`{"message":"Success"}`))
			return
		}

		rw.WriteHeader(http.StatusNotFound)
		rw.Write([]byte(`{"status":"NotFound"}`))
	})
}

// mock various behaviours for testing
func testServer(t *testing.T) string {
	return mockServer(t, func(rw http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		rw.Header().Set("Auth-Was", r.Header.Get("Authorization"))

		if r.URL.Path == "/sleep" {
			time.Sleep(1 * time.Second)
		}

		if string(body) == "length-mismatch" {
			rw.Header().Set("Content-Length", "200")
		}

		if string(body) == "set-clock" {
			now := event.Clock()
			event.Clock = func() time.Time { return now.Add(2 * time.Second) }
		}

		rw.Write(body)
	})
}

// mock proxy.supergood.ai for testing
func mockProxyServer(t *testing.T) string {

	return mockServer(t, func(rw http.ResponseWriter, r *http.Request) {

		if r.Header.Get("X-Supergood-ClientID") != clientID && r.Header.Get("X-Supergood-ClientSecret") != clientSecret {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}

		proxyEvent := event.Event{
			Request:  &event.Request{ID: "proxyId"},
			Response: &event.Response{Status: 200},
		}
		events = append(events, &proxyEvent)

		rw.Write([]byte(`{"message":"Success"}`))
	})
}

func Test_Supergood(t *testing.T) {
	baseURL := mockApiServer(t)
	telemetryURL := mockTelemetryServer(t)
	host := testServer(t)
	proxyURLStr := mockProxyServer(t)
	proxyURl, err := url.Parse(proxyURLStr)
	if err != nil {
		panic(err)
	}

	t.Setenv("SUPERGOOD_CLIENT_ID", clientID)
	t.Setenv("SUPERGOOD_CLIENT_SECRET", clientSecret)
	t.Setenv("SUPERGOOD_BASE_URL", baseURL)
	t.Setenv("SUPERGOOD_TELEMETRY_URL", telemetryURL)
	t.Setenv("SUPERGOOD_PROXY_HOST", proxyURl.Host)
	t.Setenv("SUPERGOOD_PROXY_SCHEME", proxyURl.Scheme)

	echoBody := func(t *testing.T, o *Options, body []byte) {
		reset()
		sg, err := New(o)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", host+"/echo?param=1", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "test-auth")
		resp, err := sg.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, body, b)
		isBroken := broken
		err = sg.Close()
		if !isBroken {
			require.NoError(t, err)
		} else {
			require.Error(t, err, "/post/events")
		}
	}
	echo := func(t *testing.T, o *Options) {
		body := map[string]string{
			"key": "body",
		}
		bytes, _ := json.Marshal(body)
		echoBody(t, o, bytes)
	}

	t.Run("default", func(t *testing.T) {
		echo(t, &Options{})
		require.Len(t, events, 1)
		require.Equal(t, "/echo", events[0].Request.Path)
		require.Equal(t, "param=1", events[0].Request.Search)
		require.Equal(t, host+"/echo?param=1", events[0].Request.URL)
		require.Equal(t, "POST", events[0].Request.Method)
		require.Equal(t, events[0].Response.Headers["Auth-Was"], "test-auth")
		require.Equal(t, events[0].Response.Status, 200)
		require.Equal(t, events[0].Response.StatusText, "200 OK")
	})

	t.Run("AllowedDomains=[\"herokuapp.com\"]", func(t *testing.T) {
		allowedUrl := "https://supergood-testbed.herokuapp.com/200"
		allowedDomains := []string{"herokuapp.com"}
		reset()
		sg, err := New(&Options{AllowedDomains: allowedDomains})
		require.NoError(t, err)
		sg.DefaultClient.Get(allowedUrl)
		sg.DefaultClient.Get("https://api64.ipify.org/?format=json")

		require.NoError(t, sg.Close())
		require.Len(t, events, 1)
		require.Equal(t, allowedUrl, events[0].Request.URL)
	})

	t.Run("Ignored Endpoints", func(t *testing.T) {
		reset()
		sg, err := New(&Options{})
		require.NoError(t, err)
		sg.DefaultClient.Get("https://ignored-domain.com/ignore-me")
		require.NoError(t, sg.Close())
		require.Len(t, events, 0)
	})

	t.Run("Blocked Endpoints", func(t *testing.T) {
		reset()
		sg, err := New(&Options{})
		require.NoError(t, err)
		sg.DefaultClient.Get("https://blocked-domain.com/block-me")
		require.NoError(t, sg.Close())
		require.Len(t, events, 1)
		require.Equal(t, 429, events[0].Response.Status)
	})

	t.Run("test timing", func(t *testing.T) {
		event.Clock = func() time.Time { return time.Date(2023, 01, 01, 01, 01, 01, 0, time.UTC) }
		defer func() { event.Clock = time.Now }()
		echoBody(t, &Options{}, []byte("set-clock"))

		require.Len(t, events, 1)
		require.Equal(t, time.Date(2023, 01, 01, 01, 01, 01, 0, time.UTC), events[0].Request.RequestedAt)
		require.Equal(t, time.Date(2023, 01, 01, 01, 01, 03, 0, time.UTC), events[0].Response.RespondedAt)
		require.Equal(t, 2000, events[0].Response.Duration)
	})

	t.Run("network failure", func(t *testing.T) {
		reset()
		sg, err := New(nil)
		require.NoError(t, err)

		_, err = sg.DefaultClient.Get("https://does-not-resolve.example")
		require.Error(t, err)
		require.NoError(t, sg.Close())

		require.Len(t, events, 1)
		require.Equal(t, 0, events[0].Response.Status)
		require.Equal(t, "HTTP ERROR", events[0].Response.StatusText)
		require.Contains(t, events[0].Response.Body, "no such host")
	})

	t.Run("hanging request", func(t *testing.T) {
		reset()
		sg, err := New(nil)
		require.NoError(t, err)

		_, err = sg.DefaultClient.Get("https://httpbin.org/get")
		require.NoError(t, err)
		require.NoError(t, sg.Close())

		require.Len(t, events, 1)
		require.NotNil(t, events[0].Response)
		require.Equal(t, 200, events[0].Response.Status)
	})

	t.Run("error handling on response body parsing", func(t *testing.T) {
		reset()
		sg, err := New(nil)
		require.NoError(t, err)
		defer sg.Close()

		req, err := http.NewRequest("POST", host+"/echo?param=1", strings.NewReader("length-mismatch"))
		require.NoError(t, err)
		resp, err := sg.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
		require.Error(t, err)

		req2, err2 := http.NewRequest("POST", host+"/echo?param=1", strings.NewReader("length-mismatch"))
		require.NoError(t, err2)
		resp2, err2 := http.DefaultClient.Do(req2)
		require.NoError(t, err2)
		defer resp.Body.Close()
		_, err2 = io.ReadAll(resp2.Body)
		require.Error(t, err2)

		require.Equal(t, err.Error(), err2.Error())
	})

	t.Run("test flush", func(t *testing.T) {
		reset()
		sg, err := New(&Options{FlushInterval: 1 * time.Millisecond})
		require.NoError(t, err)
		defer sg.Close()
		sg.DefaultClient.Get(host + "/echo")
		go sg.DefaultClient.Get(host + "/sleep")
		time.Sleep(10 * time.Millisecond)
		require.Len(t, events, 1)
		require.Equal(t, "/echo", events[0].Request.Path)
	})

	t.Run("error handling on close", func(t *testing.T) {
		reset()
		broken = true
		defer func() { broken = false }()
		echo(t, &Options{})
		require.Len(t, errorReports, 1)
		require.Equal(t, "supergood: got HTTP 500 Internal Server Error posting to /events", errorReports[0].Message)
		require.Equal(t, "supergood-go", errorReports[0].Payload.Name)
		// cannot be read in tests
		require.Equal(t, "unknown", errorReports[0].Payload.Version)
	})

	t.Run("handling a broken error handler", func(t *testing.T) {
		reset()
		twiceBroken = true
		defer func() { twiceBroken = false }()
		var logErr error
		sg, err := New(&Options{OnError: func(e error) { logErr = e }})
		require.NoError(t, err)
		sg.DefaultClient.Get(host + "/echo")

		err = sg.Close()
		require.Error(t, err, "/post/events")
		require.Error(t, logErr, "/post/errors")
	})

	t.Run("handling invalid client id", func(t *testing.T) {
		var logErr error
		_, err := New(&Options{OnError: func(e error) { logErr = e }, ClientID: "oops"})
		require.NoError(t, err)
		require.Error(t, logErr, "invalid ClientID")
	})

	t.Run("handling broken base url", func(t *testing.T) {
		var logErr error
		_, err := New(&Options{
			BaseURL:       "https://localhost:1",
			FlushInterval: 1 * time.Millisecond,
			OnError:       func(e error) { logErr = e },
		})
		require.NoError(t, err)
		require.Error(t, logErr, "connection refused")
	})

	t.Run("testing http clients passed as options", func(t *testing.T) {
		mockBaseClient := &http.Client{}
		mockServerChannel := make(chan int, 2)
		options := &Options{
			HTTPClient: mockWrapClient(mockBaseClient, mockServerChannel),
		}
		echo(t, options)

		count := 0
		for len(mockServerChannel) > 0 {
			<-mockServerChannel
			count++
		}
		// Four calls get tracked by the base client.
		// First to fetch the remote config
		// One for the initial mock request
		// and the last 2 are the telemetry call and event logging to the supergood backend
		require.Equal(t, 4, count)
		close(mockServerChannel)

		require.Len(t, events, 1)
	})

	t.Run("handling failed remote config initialization", func(t *testing.T) {
		allowedUrl := "https://supergood-testbed.herokuapp.com/200"
		remoteConfigBroken = true
		defer func() { remoteConfigBroken = false }()
		reset()

		sg, err := New(&Options{})
		require.NoError(t, err)
		sg.DefaultClient.Get(allowedUrl)

		require.NoError(t, sg.Close())
		// Does not capture events on failed remote config initialization
		require.Len(t, events, 0)
	})

	t.Run("handling max cache size reached", func(t *testing.T) {
		reset()
		sg, err := New(&Options{MaxCacheSizeBytes: 1})
		require.NoError(t, err)
		defer sg.Close()
		sg.DefaultClient.Get(host + "/echo")
		require.Len(t, events, 0)
	})

	t.Run("handling proxied request", func(t *testing.T) {
		reset()
		sg, err := New(&Options{})
		require.NoError(t, err)
		defer sg.Close()
		sg.DefaultClient.Get("https://api.openai.com")
		require.Len(t, events, 1)
		require.Equal(t, 200, events[0].Response.Status)
	})
}
