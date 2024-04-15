package redact

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	remoteconfig "github.com/supergoodsystems/supergood-go/pkg/remote-config"
)

type SensitiveKeyExpected struct {
	Name string
	Type string
}

func Test_Redact_All(t *testing.T) {

	t.Run("Redacts sensitive key from request and response headers and body", func(t *testing.T) {
		events := CreateEvents()
		config := CreateRemoteConfig(true)
		errors := Redact(events, config)

		require.Len(t, errors, 0)
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["key"])
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["keyInt"])
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["keyFloat"])
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["nested"].(map[string]any)["key"])
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["array"])
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["arrayOfObj"].([]map[string]any)[0]["field1"])
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["key"])
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["keyInt"])
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["keyFloat"])
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["nested"].(map[string]any)["key"])
		require.Equal(t, "", events[0].Request.Headers["key"])

		// ensure all keys tracked are redacted
		expectedKeys := []SensitiveKeyExpected{
			{
				Name: "requestBody.key",
				Type: "string",
			},
			{
				Name: "requestBody.keyInt",
				Type: "integer",
			},
			{
				Name: "requestBody.keyFloat",
				Type: "float",
			},
			{
				Name: "requestBody.nested.key",
				Type: "string",
			},
			{
				Name: "requestBody.arrayOfObj[0].field1",
				Type: "string",
			},
			{
				Name: "responseBody.key",
				Type: "string",
			},
			{
				Name: "responseBody.keyInt",
				Type: "integer",
			},
			{
				Name: "responseBody.keyFloat",
				Type: "float",
			},
			{
				Name: "responseBody.nested.key",
				Type: "string",
			},
			{
				Name: "requestHeaders.key",
				Type: "string",
			},
		}

		// Note: cannot guarantee the order of the returned sensitive keys array
		// reason for the nested forloop
		for _, expectedKey := range expectedKeys {
			for idx, sensitiveKey := range events[0].MetaData.SensitiveKeys {
				if sensitiveKey.KeyPath == expectedKey.Name {
					require.Equal(t, expectedKey.Type, sensitiveKey.Type)
					break
				}
				if idx == len(events[0].MetaData.SensitiveKeys)-1 {
					t.Errorf("Failed to find expected key: %s in returned sensitive key arrays", expectedKey)
				}
			}
		}
	})

	t.Run("Redacts sensitive keys by default with overrides", func(t *testing.T) {
		events := CreateEvents()
		config := CreateRemoteConfig(true)

		reg, _ := regexp.Compile("test-endpoint")
		cachVal := map[string]remoteconfig.EndpointCacheVal{"endpointId": {
			Id:       "test",
			Regex:    *reg,
			Location: "URL",
			Action:   "Allow",
			SensitiveKeys: []remoteconfig.SensitiveKeys{
				{
					Id:      "test-id",
					KeyPath: "responseBody.key",
					Action:  "Allow",
				},
			},
		},
		}
		config.Set("test.com", cachVal)

		errors := Redact(events, config)

		require.Len(t, errors, 0)
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["key"])
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["keyInt"])
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["keyFloat"])
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["nested"].(map[string]any)["key"])
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["array"])
		require.Equal(t, nil, events[0].Request.Body.(map[string]any)["arrayOfObj"].([]map[string]any)[0]["field1"])
		require.Equal(t, "value", events[0].Response.Body.(map[string]any)["key"])
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["keyInt"])
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["keyFloat"])
		require.Equal(t, nil, events[0].Response.Body.(map[string]any)["nested"].(map[string]any)["key"])
		require.Equal(t, "", events[0].Request.Headers["key"])

		// ensure all keys tracked are redacted
		expectedKeys := []SensitiveKeyExpected{
			{
				Name: "requestBody.key",
				Type: "string",
			},
			{
				Name: "requestBody.keyInt",
				Type: "integer",
			},
			{
				Name: "requestBody.keyFloat",
				Type: "float",
			},
			{
				Name: "requestBody.nested.key",
				Type: "string",
			},
			{
				Name: "requestBody.arrayOfObj[0].field1",
				Type: "string",
			},
			// NOTE: Below entry should not belong in sensitive keys since its explicitly allowed above
			// {
			// 	Name: "responseBody.key",
			// 	Type: "string",
			// },
			{
				Name: "responseBody.keyInt",
				Type: "integer",
			},
			{
				Name: "responseBody.keyFloat",
				Type: "float",
			},
			{
				Name: "responseBody.nested.key",
				Type: "string",
			},
			{
				Name: "requestHeaders.key",
				Type: "string",
			},
		}

		// Note: cannot guarantee the order of the returned sensitive keys array
		// reason for the nested forloop
		for _, expectedKey := range expectedKeys {
			for idx, sensitiveKey := range events[0].MetaData.SensitiveKeys {
				if sensitiveKey.KeyPath == expectedKey.Name {
					require.Equal(t, expectedKey.Type, sensitiveKey.Type)
					break
				}
				if idx == len(events[0].MetaData.SensitiveKeys)-1 {
					t.Errorf("Failed to find expected key: %s in returned sensitive key arrays", expectedKey)
				}
			}
		}
	})
}
