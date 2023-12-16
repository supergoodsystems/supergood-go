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
		cacheVal := remoteconfig.EndpointCacheVal{
			Regex:    *regex,
			Location: "path",
			Action:   "Accept",
			SensitiveKeys: []remoteconfig.SensitiveKeys{
				{KeyPath: "requestBody.key"},
				{KeyPath: "requestBody.keyInt"},
				{KeyPath: "requestBody.keyFloat"},
				{KeyPath: "requestBody.nested.key"},
				{KeyPath: "requestBody.array"},
				{KeyPath: "requestBody.arrayOfObj[].field1"},
			},
		}
		config.Set("test.com", map[string]remoteconfig.EndpointCacheVal{"endpointId": cacheVal})
		errors := Redact(events, config)

		require.Len(t, errors, 0)
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
		// successfully redacts array
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["array"])
		require.Equal(t, "requestBody.array", events[0].MetaData.SensitiveKeys[4].KeyPath)
		require.Equal(t, "slice", events[0].MetaData.SensitiveKeys[4].Type)
		// successfully redacts nested object within array
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["arrayOfObj"].([]map[string]any)[0]["field1"])
		require.Equal(t, "requestBody.arrayOfObj[0].field1", events[0].MetaData.SensitiveKeys[5].KeyPath)
		require.Equal(t, "string", events[0].MetaData.SensitiveKeys[5].Type)
	})

	t.Run("Redact sensitive key from response body", func(t *testing.T) {
		events := createEvents()
		config := createRemoteConfig()
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := remoteconfig.EndpointCacheVal{
			Regex:    *regex,
			Location: "path",
			Action:   "Accept",
			SensitiveKeys: []remoteconfig.SensitiveKeys{
				{KeyPath: "responseBody.key"},
				{KeyPath: "responseBody.keyInt"},
				{KeyPath: "responseBody.keyFloat"},
				{KeyPath: "responseBody.nested.key"},
			},
		}
		config.Set("test.com", map[string]remoteconfig.EndpointCacheVal{"endpointId": cacheVal})
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
		cacheVal := remoteconfig.EndpointCacheVal{
			Regex:         *regex,
			Location:      "path",
			Action:        "Accept",
			SensitiveKeys: []remoteconfig.SensitiveKeys{{KeyPath: "requestHeaders.key"}},
		}
		config.Set("test.com", map[string]remoteconfig.EndpointCacheVal{"endpointId": cacheVal})
		errors := Redact(events, config)
		require.Len(t, errors, 0)
		require.Equal(t, "", events[0].Request.Headers["key"])
	})

	t.Run("Handles invalid sensitive keys gracefully", func(t *testing.T) {
		events := createEvents()
		config := createRemoteConfig()
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := remoteconfig.EndpointCacheVal{
			Regex:         *regex,
			Location:      "path",
			Action:        "Accept",
			SensitiveKeys: []remoteconfig.SensitiveKeys{{KeyPath: "requestBody.non-existant-key"}},
		}
		config.Set("test.com", map[string]remoteconfig.EndpointCacheVal{"endpointId": cacheVal})
		errors := Redact(events, config)
		require.Len(t, errors, 1)
	})

	t.Run("Does not redact in case no matching domain in cache", func(t *testing.T) {
		events := createEvents()
		config := createRemoteConfig()
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := remoteconfig.EndpointCacheVal{
			Regex:         *regex,
			Location:      "path",
			Action:        "Accept",
			SensitiveKeys: []remoteconfig.SensitiveKeys{{KeyPath: "requestHeaders.key"}},
		}
		config.Set("not-test.com", map[string]remoteconfig.EndpointCacheVal{"endpointId": cacheVal})
		errors := Redact(events, config)
		require.Len(t, errors, 0)
		require.Equal(t, "value", events[0].Request.Headers["key"])
	})

	t.Run("Does not redact in case no matching endpoint in cache", func(t *testing.T) {
		events := createEvents()
		config := createRemoteConfig()
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := remoteconfig.EndpointCacheVal{
			Regex:         *regex,
			Location:      "path",
			Action:        "Accept",
			SensitiveKeys: []remoteconfig.SensitiveKeys{{KeyPath: "requestHeaders.key"}},
		}
		config.Set("test.com", map[string]remoteconfig.EndpointCacheVal{"non-matching-endpoint-id": cacheVal})
		errors := Redact(events, config)
		require.Len(t, errors, 0)
		require.Equal(t, "value", events[0].Request.Headers["key"])
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
				"array": []string{"item1", "item2"},
				"arrayOfObj": []map[string]any{
					{
						"field1": "value1",
						"field2": "value2",
					},
					{
						"field1": "value3",
						"field2": "value4",
					},
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
		MetaData: event.MetaData{
			EndpointId: "endpointId",
		},
	}
	events = append(events, event)
	return events
}
