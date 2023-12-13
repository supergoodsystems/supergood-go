package ignore

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	remoteconfig "github.com/supergoodsystems/supergood-go/internal/remote-config"
)

func Test_Ignore(t *testing.T) {
	t.Run("Successfully ignores request for path based endpoint", func(t *testing.T) {
		config := createRemoteConfig()
		regex, _ := regexp.Compile("ignore-endpoint")
		config.Set("test.com", []remoteconfig.EndpointCacheVal{
			{
				Regex:    *regex,
				Location: "path",
				Action:   "Ignore",
			},
		})
		req, _ := http.NewRequest("GET", "https://test.com/ignore-endpoint", nil)
		ignore, errors := ShouldIgnoreRequest(req, config)
		require.Equal(t, true, ignore)
		require.Len(t, errors, 0)
	})

	t.Run("Successfully accepts request for path based endpoint", func(t *testing.T) {
		config := createRemoteConfig()
		regex, _ := regexp.Compile("ignore-endpoint")
		config.Set("test.com", []remoteconfig.EndpointCacheVal{
			{
				Regex:    *regex,
				Location: "path",
				Action:   "Accept",
			},
		})
		req, _ := http.NewRequest("GET", "https://test.com/ignore-endpoint", nil)
		ignore, errors := ShouldIgnoreRequest(req, config)
		require.Equal(t, false, ignore)
		require.Len(t, errors, 0)
	})

	t.Run("Successfully ignores request for header based endpoint", func(t *testing.T) {
		config := createRemoteConfig()
		regex, _ := regexp.Compile("ignore-value")
		config.Set("test.com", []remoteconfig.EndpointCacheVal{
			{
				Regex:    *regex,
				Location: "requestHeaders",
				Action:   "Ignore",
			},
		})
		req, _ := http.NewRequest("GET", "https://test.com/endpoint", nil)
		req.Header = map[string][]string{
			"Foo": {"ignore-value"},
		}
		ignore, errors := ShouldIgnoreRequest(req, config)
		require.Equal(t, true, ignore)
		require.Len(t, errors, 0)
	})

	t.Run("Successfully accepts request for header based endpoint", func(t *testing.T) {
		config := createRemoteConfig()
		regex, _ := regexp.Compile("accept-value")
		config.Set("test.com", []remoteconfig.EndpointCacheVal{
			{
				Regex:    *regex,
				Location: "requestHeaders",
				Action:   "Accept",
			},
		})
		req, _ := http.NewRequest("GET", "https://test.com/endpoint", nil)
		req.Header = map[string][]string{
			"Foo": {"accept-value"},
		}
		ignore, errors := ShouldIgnoreRequest(req, config)
		require.Equal(t, false, ignore)
		require.Len(t, errors, 0)
	})

	t.Run("Successfully ignores request for request body based endpoint", func(t *testing.T) {
		config := createRemoteConfig()
		regex, _ := regexp.Compile("hello")
		config.Set("test.com", []remoteconfig.EndpointCacheVal{
			{
				Regex:    *regex,
				Location: "requestBody.field1",
				Action:   "Ignore",
			},
		})
		requestBody := map[string]any{
			"field1": "hello",
		}
		body, _ := json.Marshal(requestBody)
		req, _ := http.NewRequest("POST", "https://test.com/endpoint", bytes.NewReader(body))
		ignore, errors := ShouldIgnoreRequest(req, config)
		require.Equal(t, true, ignore)
		require.Len(t, errors, 0)
	})

	t.Run("Successfully accepts request for request body based endpoint", func(t *testing.T) {
		config := createRemoteConfig()
		regex, _ := regexp.Compile("hello")
		config.Set("test.com", []remoteconfig.EndpointCacheVal{
			{
				Regex:    *regex,
				Location: "requestBody.field1",
				Action:   "Accept",
			},
		})
		requestBody := map[string]any{
			"field1": "hello",
		}
		body, _ := json.Marshal(requestBody)
		req, _ := http.NewRequest("POST", "https://test.com/endpoint", bytes.NewReader(body))
		ignore, errors := ShouldIgnoreRequest(req, config)
		require.Equal(t, false, ignore)
		require.Len(t, errors, 0)
	})

	t.Run("Successfully ignores request for nested request body based endpoint", func(t *testing.T) {
		config := createRemoteConfig()
		regex, _ := regexp.Compile("hello")
		config.Set("test.com", []remoteconfig.EndpointCacheVal{
			{
				Regex:    *regex,
				Location: "requestBody.field1.field2",
				Action:   "Ignore",
			},
		})
		requestBody := map[string]any{
			"field1": map[string]any{
				"field2": "hello",
			},
		}
		body, _ := json.Marshal(requestBody)
		req, _ := http.NewRequest("POST", "https://test.com/endpoint", bytes.NewReader(body))
		ignore, errors := ShouldIgnoreRequest(req, config)
		require.Equal(t, true, ignore)
		require.Len(t, errors, 0)
	})

	t.Run("Successfully accepts request for nested request body based endpoint", func(t *testing.T) {
		config := createRemoteConfig()
		regex, _ := regexp.Compile("hello")
		config.Set("test.com", []remoteconfig.EndpointCacheVal{
			{
				Regex:    *regex,
				Location: "requestBody.field1.field2",
				Action:   "Accept",
			},
		})
		requestBody := map[string]any{
			"field1": map[string]any{
				"field2": "hello",
			},
		}
		body, _ := json.Marshal(requestBody)
		req, _ := http.NewRequest("POST", "https://test.com/endpoint", bytes.NewReader(body))
		ignore, errors := ShouldIgnoreRequest(req, config)
		require.Equal(t, false, ignore)
		require.Len(t, errors, 0)
	})
}

func createRemoteConfig() *remoteconfig.RemoteConfig {
	config := remoteconfig.New(remoteconfig.RemoteConfigOpts{
		HandleError: func(error) {},
	})
	return &config
}
