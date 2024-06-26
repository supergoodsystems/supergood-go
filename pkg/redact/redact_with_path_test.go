package redact

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	remoteconfig "github.com/supergoodsystems/supergood-go/pkg/remote-config"
)

func Test_Redact_With_Path(t *testing.T) {

	t.Run("Redact sensitive key from request body", func(t *testing.T) {
		events := CreateEvents()
		config := CreateRemoteConfig(false)
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := remoteconfig.EndpointCacheVal{
			Regex:    *regex,
			Location: "path",
			Action:   "Accept",
			SensitiveKeys: []remoteconfig.SensitiveKeys{
				{KeyPath: "requestBody.key", Action: "REDACT"},
				{KeyPath: "requestBody.keyInt", Action: "REDACT"},
				{KeyPath: "requestBody.keyFloat", Action: "REDACT"},
				{KeyPath: "requestBody.nested.key", Action: "REDACT"},
				{KeyPath: "requestBody.array", Action: "REDACT"},
				{KeyPath: "requestBody.arrayOfObj[].field1", Action: "REDACT"},
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
		require.Equal(t, "integer", events[0].MetaData.SensitiveKeys[1].Type)
		// successfully redacts int float
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["keyFloat"])
		require.Equal(t, "requestBody.keyFloat", events[0].MetaData.SensitiveKeys[2].KeyPath)
		require.Equal(t, "float", events[0].MetaData.SensitiveKeys[2].Type)
		// successfully redacts nested string key
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["nested"].(map[string]any)["key"])
		require.Equal(t, "requestBody.nested.key", events[0].MetaData.SensitiveKeys[3].KeyPath)
		require.Equal(t, "string", events[0].MetaData.SensitiveKeys[3].Type)
		// successfully redacts array
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["array"])
		require.Equal(t, "requestBody.array", events[0].MetaData.SensitiveKeys[4].KeyPath)
		require.Equal(t, "array", events[0].MetaData.SensitiveKeys[4].Type)
		// successfully redacts nested object within array
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["arrayOfObj"].([]map[string]any)[0]["field1"])
		require.Equal(t, "requestBody.arrayOfObj[0].field1", events[0].MetaData.SensitiveKeys[5].KeyPath)
		require.Equal(t, "string", events[0].MetaData.SensitiveKeys[5].Type)
	})

	t.Run("Redact sensitive key from response body", func(t *testing.T) {
		events := CreateEvents()
		config := CreateRemoteConfig(false)
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := remoteconfig.EndpointCacheVal{
			Regex:    *regex,
			Location: "path",
			Action:   "Accept",
			SensitiveKeys: []remoteconfig.SensitiveKeys{
				{KeyPath: "responseBody.key", Action: "REDACT"},
				{KeyPath: "responseBody.keyInt", Action: "REDACT"},
				{KeyPath: "responseBody.keyFloat", Action: "REDACT"},
				{KeyPath: "responseBody.nested.key", Action: "REDACT"},
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
		require.Equal(t, "integer", events[0].MetaData.SensitiveKeys[1].Type)
		// successfully redacts int float
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["keyFloat"])
		require.Equal(t, "responseBody.keyFloat", events[0].MetaData.SensitiveKeys[2].KeyPath)
		require.Equal(t, "float", events[0].MetaData.SensitiveKeys[2].Type)
		// successfully redacts nested string key
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["nested"].(map[string]any)["key"])
		require.Equal(t, "responseBody.nested.key", events[0].MetaData.SensitiveKeys[3].KeyPath)
		require.Equal(t, "string", events[0].MetaData.SensitiveKeys[3].Type)
	})

	t.Run("Redact sensitive key from request headers", func(t *testing.T) {
		events := CreateEvents()
		config := CreateRemoteConfig(false)
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := remoteconfig.EndpointCacheVal{
			Regex:         *regex,
			Location:      "path",
			Action:        "Accept",
			SensitiveKeys: []remoteconfig.SensitiveKeys{{KeyPath: "requestHeaders.key", Action: "REDACT"}},
		}
		config.Set("test.com", map[string]remoteconfig.EndpointCacheVal{"endpointId": cacheVal})
		errors := Redact(events, config)
		require.Len(t, errors, 0)
		require.Equal(t, "", events[0].Request.Headers["key"])
	})

	t.Run("Handles invalid sensitive keys gracefully", func(t *testing.T) {
		events := CreateEvents()
		config := CreateRemoteConfig(false)
		regex, _ := regexp.Compile("test-endpoint")
		cacheVal := remoteconfig.EndpointCacheVal{
			Regex:         *regex,
			Location:      "path",
			Action:        "Accept",
			SensitiveKeys: []remoteconfig.SensitiveKeys{{KeyPath: "requestBody.non-existant-key", Action: "REDACT"}},
		}
		config.Set("test.com", map[string]remoteconfig.EndpointCacheVal{"endpointId": cacheVal})
		errors := Redact(events, config)
		require.Len(t, errors, 1)
	})

	t.Run("Does not redact in case no matching domain in cache", func(t *testing.T) {
		events := CreateEvents()
		config := CreateRemoteConfig(false)
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
		events := CreateEvents()
		config := CreateRemoteConfig(false)
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
