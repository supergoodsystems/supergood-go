package redact

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supergoodsystems/supergood-go/internal/event"
	remoteconfig "github.com/supergoodsystems/supergood-go/internal/remote-config"
)

func Test_Redact(t *testing.T) {

	t.Run("Redact sensitive key from request body", func(t *testing.T) {
		events := createEvents()
		config := createRemoteConfig()
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := []remoteconfig.EndpointCacheVal{
			{
				Regex:    *regex,
				Location: "path",
				Action:   "Accept",
				SensitiveKeys: []remoteconfig.SensitiveKeys{
					{KeyPath: "requestBody.key"},
					{KeyPath: "requestBody.nested.key"},
				},
			},
		}
		config.Set("test.com", cacheVal)
		Redact(events, config, func(error) {})

		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["key"])
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["nested"].(map[string]any)["key"])
	})

	t.Run("Redact sensitive key from response body", func(t *testing.T) {
		events := createEvents()
		config := createRemoteConfig()
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := []remoteconfig.EndpointCacheVal{
			{
				Regex:    *regex,
				Location: "path",
				Action:   "Accept",
				SensitiveKeys: []remoteconfig.SensitiveKeys{
					{KeyPath: "responseBody.key"},
					{KeyPath: "responseBody.nested.key"},
				},
			},
		}
		config.Set("test.com", cacheVal)
		Redact(events, config, func(error) {})
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["key"])
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["nested"].(map[string]any)["key"])
	})
	t.Run("Redact sensitive key from request headers", func(t *testing.T) {
		events := createEvents()
		config := createRemoteConfig()
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := []remoteconfig.EndpointCacheVal{
			{
				Regex:         *regex,
				Location:      "path",
				Action:        "Accept",
				SensitiveKeys: []remoteconfig.SensitiveKeys{{KeyPath: "requestHeaders.key"}},
			},
		}
		config.Set("test.com", cacheVal)
		Redact(events, config, func(error) {})
		require.Equal(t, "", events[0].Request.Headers["key"])
	})
}

func createRemoteConfig() *remoteconfig.RemoteConfig {
	config := remoteconfig.New(remoteconfig.RemoteConfigOpts{
		HandleError: func(error) {},
	})
	return &config
}

func createEvents() []*event.Event {
	events := []*event.Event{}
	event := &event.Event{
		Request: &event.Request{
			URL:  "test.com/test-endpoint",
			Path: "/test-endpoint",
			Body: map[string]any{
				"key": "value",
				"nested": map[string]any{
					"key": "value",
				},
			},
			Headers: map[string]string{
				"key": "value",
			},
		},
		Response: &event.Response{
			Body: map[string]any{
				"key": "value",
				"nested": map[string]any{
					"key": "value",
				},
			},
		},
	}
	events = append(events, event)
	return events
}

// func Test_Supergood(t *testing.T) {
// 	baseURL := mockApiServer(t)
// 	host := testServer(t)
// 	t.Setenv("SUPERGOOD_CLIENT_ID", clientID)
// 	t.Setenv("SUPERGOOD_CLIENT_SECRET", clientSecret)
// 	t.Setenv("SUPERGOOD_BASE_URL", baseURL)

// 	echoBody := func(t *testing.T, o *Options, body []byte) {
// 		reset()
// 		sg, err := New(o)
// 		require.NoError(t, err)
// 		req, err := http.NewRequest("POST", host+"/echo?param=1", bytes.NewReader(body))
// 		require.NoError(t, err)
// 		req.Header.Set("Authorization", "test-auth")
// 		resp, err := sg.DefaultClient.Do(req)
// 		require.NoError(t, err)
// 		defer resp.Body.Close()
// 		b, err := io.ReadAll(resp.Body)
// 		require.NoError(t, err)
// 		require.Equal(t, body, b)
// 		isBroken := broken
// 		err = sg.Close()
// 		if !isBroken {
// 			require.NoError(t, err)
// 		} else {
// 			require.Error(t, err, "/post/events")
// 		}
// 	}
// 	echo := func(t *testing.T, o *Options) {
// 		body := map[string]string{
// 			"key": "body",
// 		}
// 		bytes, _ := json.Marshal(body)
// 		echoBody(t, o, bytes)
// 	}

// 	t.Run("default", func(t *testing.T) {
// 		echo(t, &Options{RedactResponseBodyKeys: map[string][]string{host: []string{"key"}}})
// 		require.Len(t, events, 1)
// 		require.Empty(t, events[0].Response.Body)
// 		require.Equal(t, "/echo", events[0].Request.Path)
// 		require.Equal(t, "param=1", events[0].Request.Search)
// 		require.Equal(t, host+"/echo?param=1", events[0].Request.URL)
// 		require.Equal(t, "POST", events[0].Request.Method)
// 		require.Equal(t, events[0].Request.Headers["Authorization"], "redacted:dba430468af6b5fc3c22facf6dc871ce6e3801b9")
// 		require.Equal(t, events[0].Response.Headers["Auth-Was"], "test-auth")
// 		require.Equal(t, events[0].Response.Status, 200)
// 		require.Equal(t, events[0].Response.StatusText, "200 OK")
// 	})

// 	t.Run("RedactResponseBody=true", func(t *testing.T) {
// 		echo(t, &Options{RedactResponseBody: true})
// 		require.Len(t, events, 1)
// 		require.Equal(t, "aaaa*aaaa", events[0].Response.Body)
// 	})
// 	t.Run("RedactRequestBody=true", func(t *testing.T) {
// 		echo(t, &Options{RedactRequestBody: true})
// 		require.Len(t, events, 1)
// 		require.Equal(t, "aaaa*aaaa", events[0].Request.Body)
// 	})

// 	t.Run("AllowedDomains=[\"herokuapp.com\"]", func(t *testing.T) {
// 		allowedUrl := "https://supergood-testbed.herokuapp.com/200"
// 		allowedDomains := []string{"herokuapp.com"}
// 		reset()
// 		sg, err := New(&Options{AllowedDomains: allowedDomains})
// 		require.NoError(t, err)
// 		sg.DefaultClient.Get(allowedUrl)
// 		sg.DefaultClient.Get("https://api64.ipify.org/?format=json")

// 		require.NoError(t, sg.Close())
// 		require.Len(t, events, 1)
// 		require.Equal(t, allowedUrl, events[0].Request.URL)
// 	})

// 	t.Run("Ignored Endpoints", func(t *testing.T) {
// 		reset()
// 		sg, err := New(&Options{})
// 		require.NoError(t, err)
// 		sg.DefaultClient.Get("https://ignored-domain.com/ignore-me")
// 		require.NoError(t, sg.Close())
// 		require.Len(t, events, 0)
// 	})

// 	t.Run("redacting nested string values", func(t *testing.T) {
// 		options := &Options{RedactResponseBodyKeys: map[string][]string{host: []string{"nested.key", "nested.other"}}}
// 		echoBody(t, options, []byte(`{"nested":{"key":"value"},"other":"value"}`))
// 		require.Len(t, events, 1)
// 		require.Equal(t, map[string]any{"nested": map[string]any{"key": ""}, "other": ""}, events[0].Request.Body)
// 	})

// 	t.Run("redacting nested integer values", func(t *testing.T) {
// 		options := &Options{RedactResponseBodyKeys: map[string][]string{host: []string{"nested.key", "nested.other"}}}
// 		echoBody(t, options, []byte(`{"nested":{"key":999},"other":999}`))
// 		require.Len(t, events, 1)
// 		require.Equal(t, map[string]any{"nested": map[string]any{"key": 0}, "other": 0}, events[0].Request.Body)
// 	})

// 	t.Run("redacting nested float values", func(t *testing.T) {
// 		options := &Options{RedactResponseBodyKeys: map[string][]string{host: []string{"nested.key", "nested.other"}}}
// 		echoBody(t, options, []byte(`{"nested":{"key":999.99},"other":999.99}`))
// 		require.Len(t, events, 1)
// 		require.Equal(t, map[string]any{"nested": map[string]any{"key": 0}, "other": 0}, events[0].Request.Body)
// 	})

// 	t.Run("redacting nested array values", func(t *testing.T) {
// 		options := &Options{RedactResponseBodyKeys: map[string][]string{host: []string{"nested.[].key", "nested.[].other"}}}
// 		echoBody(t, options, []byte(`{"nested":[{"key":"value"}],"other":["value"]}`))
// 		require.Len(t, events, 1)
// 		require.Equal(t, map[string]any{"nested": []any{map[string]any{"key": ""}}, "other": []any{""}}, events[0].Request.Body)
// 	})

// 	t.Run("redacting nested boolean values", func(t *testing.T) {
// 		options := &Options{RedactResponseBodyKeys: map[string][]string{host: []string{"nested.key", "nested.other"}}}
// 		echoBody(t, options, []byte(`{"nested":{"key":true},"other":true}`))
// 		require.Len(t, events, 1)
// 		require.Equal(t, map[string]any{"nested": map[string]any{"key": false}, "other": false}, events[0].Request.Body)
// 	})

// 	t.Run("redacting nested non-ASCII values", func(t *testing.T) {
// 		options := &Options{RedactResponseBodyKeys: map[string][]string{host: []string{"nested.key", "nested.other"}}}
// 		echoBody(t, options, []byte(`{"nested":{"key":"สวัสดี"},"other":"ลาก่อน"}`))
// 		require.Len(t, events, 1)
// 		require.Equal(t, map[string]any{"nested": map[string]any{"key": ""}, "other": ""}, events[0].Request.Body)
// 	})

// 	t.Run("redacting nil values", func(t *testing.T) {
// 		options := &Options{RedactResponseBodyKeys: map[string][]string{host: []string{"nested.key", "nested.other"}}}
// 		echoBody(t, options, []byte(`{"nested":{"key": null},"other": null}`))
// 		require.Len(t, events, 1)
// 		require.Equal(t, map[string]any{"nested": map[string]any{"key": nil}, "other": nil}, events[0].Request.Body)
// 	})

// 	t.Run("ignoring redaction for nested request keys", func(t *testing.T) {
// 		options := &Options{RedactResponseBodyKeys: map[string][]string{host: []string{"nested.other"}}}
// 		echoBody(t, options, []byte(`{"nested":{"key":"value"},"other":"value"}`))
// 		require.Len(t, events, 1)
// 		require.Equal(t, map[string]any{"nested": map[string]any{"key": "value"}, "other": ""}, events[0].Request.Body)
// 	})

// 	t.Run("valid JSON body", func(t *testing.T) {
// 		echoBody(t, &Options{RedactRequestBody: true}, []byte(`{"ok":200}`))
// 		require.Len(t, events, 1)
// 		require.Equal(t, map[string]any{"ok": float64(111)}, events[0].Request.Body)
// 	})

// 	t.Run("binary body", func(t *testing.T) {
// 		echoBody(t, &Options{RedactRequestBody: true}, []byte{0xff, 0x00, 0xff, 0x00})
// 		require.Len(t, events, 1)
// 		// String = "/wD/AA=="
// 		require.Equal(t, "binary", events[0].Request.Body)
// 	})

// 	t.Run("RedactHeaders", func(t *testing.T) {
// 		echo(t, &Options{RedactRequestHeaderKeys: map[string][]string{host: []string{"Authorization"}}})
// 		require.Len(t, events, 1)
// 		require.NotNil(t, events[0].Request)
// 		require.Empty(t, events[0].Request.Headers["Authorization"])
// 	})
// }
