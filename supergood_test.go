package supergood

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var events []*event
var errors []*errorReport
var broken bool
var twiceBroken bool

func reset() {
	events = []*event{}
	errors = []*errorReport{}
}

var clientID = "test_client_id"
var clientSecret = "test_client_secret"

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

// mock dashboard.supergood.ai for testing
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

		if twiceBroken {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte(`Oops`))
			return
		}

		if r.URL.Path == "/api/errors" && r.Method == "POST" {
			newErr := &errorReport{}
			err := json.NewDecoder(r.Body).Decode(&newErr)
			require.NoError(t, err)
			errors = append(errors, newErr)

			rw.Write([]byte(`{"message":"Success"}`))
			return
		}

		if broken {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte(`Oops`))
			return
		}

		if r.URL.Path == "/api/events" && r.Method == "POST" {
			newEvents := []*event{}
			err := json.NewDecoder(r.Body).Decode(&newEvents)
			require.NoError(t, err)
			events = append(events, newEvents...)

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
			now := clock()
			clock = func() time.Time { return now.Add(2 * time.Second) }
		}

		rw.Write(body)
	})
}

func Test_Supergood(t *testing.T) {
	baseURL := mockApiServer(t)
	host := testServer(t)
	t.Setenv("SUPERGOOD_CLIENT_ID", clientID)
	t.Setenv("SUPERGOOD_CLIENT_SECRET", clientSecret)
	t.Setenv("SUPERGOOD_BASE_URL", baseURL)

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
		echoBody(t, o, []byte("test-body"))
	}

	t.Run("default", func(t *testing.T) {
		echo(t, &Options{RecordResponseBody: false})
		require.Len(t, events, 1)
		require.Nil(t, events[0].Response.Body)
		require.Nil(t, events[0].Request.Body)
		require.Equal(t, "/echo", events[0].Request.Path)
		require.Equal(t, "param=1", events[0].Request.Search)
		require.Equal(t, host+"/echo?param=1", events[0].Request.URL)
		require.Equal(t, "POST", events[0].Request.Method)
		require.Equal(t, events[0].Request.Headers["Authorization"], "redacted:dba430468af6b5fc3c22facf6dc871ce6e3801b9")
		require.Equal(t, events[0].Response.Headers["Auth-Was"], "test-auth")
		require.Equal(t, events[0].Response.Status, 200)
		require.Equal(t, events[0].Response.StatusText, "200 OK")
	})

	t.Run("RecordResponseBody=true", func(t *testing.T) {
		echo(t, &Options{RecordResponseBody: true})
		require.Len(t, events, 1)
		require.Equal(t, "test-body", events[0].Response.Body)
	})
	t.Run("RecordRequestBody=true", func(t *testing.T) {
		echo(t, &Options{RecordRequestBody: true})
		require.Len(t, events, 1)
		require.Equal(t, "test-body", events[0].Request.Body)
	})

	t.Run("valid JSON body", func(t *testing.T) {
		echoBody(t, &Options{RecordRequestBody: true}, []byte(`{"ok":200}`))
		require.Len(t, events, 1)
		require.Equal(t, map[string]any{"ok": float64(200)}, events[0].Request.Body)
	})

	t.Run("binary body", func(t *testing.T) {
		echoBody(t, &Options{RecordRequestBody: true}, []byte{0xff, 0x00, 0xff, 0x00})
		require.Len(t, events, 1)
		require.Equal(t, "/wD/AA==", events[0].Request.Body)
	})

	t.Run("RedactHeaders", func(t *testing.T) {
		echo(t, &Options{RedactHeaders: map[string]bool{"AUTH-WAS": true}})
		require.Len(t, events, 1)
		require.Equal(t, events[0].Request.Headers["Authorization"], "test-auth")
		require.Equal(t, events[0].Response.Headers["Auth-Was"], "redacted:dba430468af6b5fc3c22facf6dc871ce6e3801b9")
	})

	t.Run("SelectRequests", func(t *testing.T) {
		echo(t, &Options{
			SelectRequests: func(r *http.Request) bool {
				if r.Method == "POST" && r.URL.Path == "/echo" {
					return false
				}
				return true
			},
		})
		require.Len(t, events, 0)
	})

	t.Run("test timing", func(t *testing.T) {
		clock = func() time.Time { return time.Date(2023, 01, 01, 01, 01, 01, 0, time.UTC) }
		defer func() { clock = time.Now }()
		echoBody(t, nil, []byte("set-clock"))

		require.Equal(t, time.Date(2023, 01, 01, 01, 01, 01, 0, time.UTC), events[0].Request.RequestedAt)
		require.Equal(t, time.Date(2023, 01, 01, 01, 01, 03, 0, time.UTC), events[0].Response.RespondedAt)
		require.Equal(t, float64(2000), events[0].Response.Duration)
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

	t.Run("error handling on response body parsing", func(t *testing.T) {
		reset()
		sg, err := New(&Options{RecordResponseBody: true})
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
		broken = true
		defer func() { broken = false }()
		echo(t, nil)
		require.Len(t, errors, 1)
		require.Equal(t, "supergood: got HTTP 500 Internal Server Error posting to /api/events", errors[0].Message)
		require.Equal(t, "supergood-go", errors[0].Payload.Name)
		// cannot be read in tests
		require.Equal(t, "unknown", errors[0].Payload.Version)
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
		sg, err := New(&Options{OnError: func(e error) { logErr = e }, ClientID: "oops"})
		require.NoError(t, err)
		sg.DefaultClient.Get(host + "/echo")
		err = sg.Close()
		require.Error(t, err, "invalid ClientID")
		require.NoError(t, logErr)
	})

	t.Run("handling broken base url", func(t *testing.T) {
		var logErrs []error

		sg, err := New(&Options{
			OnError:       func(e error) { logErrs = append(logErrs, e) },
			BaseURL:       "https://does-not-resolve.local",
			FlushInterval: 1 * time.Millisecond,
		})
		require.NoError(t, err)
		sg.DefaultClient.Get(host + "/echo")
		time.Sleep(50 * time.Millisecond)

		require.Len(t, logErrs, 2)
		require.Error(t, logErrs[0], "/post/events")
		require.Error(t, logErrs[1], "/post/errors")
		sg.Close()
	})
}
