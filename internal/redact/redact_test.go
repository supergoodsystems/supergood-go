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
					{KeyPath: "requestBody.keyInt"},
					{KeyPath: "requestBody.keyFloat"},
					{KeyPath: "requestBody.nested.key"},
				},
			},
		}
		config.Set("test.com", cacheVal)
		Redact(events, config)

		// successfully redacts string key
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["key"])
		require.Equal(t, "requestBody.key", events[0].MetaData.SensitiveKeys[0].KeyPath)
		require.Equal(t, "string", events[0].MetaData.SensitiveKeys[0].Type)
		// successfully redacts int key
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["keyInt"])
		require.Equal(t, "requestBody.keyInt", events[0].MetaData.SensitiveKeys[1].KeyPath)
		require.Equal(t, "int", events[0].MetaData.SensitiveKeys[1].Type)
		// successfully redacts int float
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["keyFloat"])
		require.Equal(t, "requestBody.keyFloat", events[0].MetaData.SensitiveKeys[2].KeyPath)
		require.Equal(t, "float64", events[0].MetaData.SensitiveKeys[2].Type)
		// successfully redacts nested string key
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["nested"].(map[string]any)["key"])
		require.Equal(t, "requestBody.nested.key", events[0].MetaData.SensitiveKeys[3].KeyPath)
		require.Equal(t, "string", events[0].MetaData.SensitiveKeys[3].Type)
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
					{KeyPath: "responseBody.keyInt"},
					{KeyPath: "responseBody.keyFloat"},
					{KeyPath: "responseBody.nested.key"},
				},
			},
		}
		config.Set("test.com", cacheVal)
		errors := Redact(events, config)
		require.Len(t, errors, 0)
		// successfully redacts string key
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["key"])
		require.Equal(t, "responseBody.key", events[0].MetaData.SensitiveKeys[0].KeyPath)
		require.Equal(t, "string", events[0].MetaData.SensitiveKeys[0].Type)
		// successfully redacts int key
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["keyInt"])
		require.Equal(t, "responseBody.keyInt", events[0].MetaData.SensitiveKeys[1].KeyPath)
		require.Equal(t, "int", events[0].MetaData.SensitiveKeys[1].Type)
		// successfully redacts int float
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["keyFloat"])
		require.Equal(t, "responseBody.keyFloat", events[0].MetaData.SensitiveKeys[2].KeyPath)
		require.Equal(t, "float64", events[0].MetaData.SensitiveKeys[2].Type)
		// successfully redacts nested string key
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["nested"].(map[string]any)["key"])
		require.Equal(t, "responseBody.nested.key", events[0].MetaData.SensitiveKeys[3].KeyPath)
		require.Equal(t, "string", events[0].MetaData.SensitiveKeys[3].Type)
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
		errors := Redact(events, config)
		require.Len(t, errors, 0)
		require.Equal(t, "", events[0].Request.Headers["key"])
	})

	t.Run("Handles invalid sensitive keys gracefully", func(t *testing.T) {
		events := createEvents()
		config := createRemoteConfig()
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := []remoteconfig.EndpointCacheVal{
			{
				Regex:         *regex,
				Location:      "path",
				Action:        "Accept",
				SensitiveKeys: []remoteconfig.SensitiveKeys{{KeyPath: "requestBody.non-existant-key"}},
			},
		}
		config.Set("test.com", cacheVal)
		errors := Redact(events, config)
		require.Len(t, errors, 1)
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
				"key":      "value",
				"keyInt":   1,
				"keyFloat": 1.1,
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
				"key":      "value",
				"keyInt":   1,
				"keyFloat": 1.1,
				"nested": map[string]any{
					"key": "value",
				},
			},
		},
	}
	events = append(events, event)
	return events
}
