package ignore

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	remoteconfig "github.com/supergoodsystems/supergood-go/internal/remote-config"
)

func Test_Ignore(t *testing.T) {
	t.Run("Successfully ignores request", func(t *testing.T) {
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

	t.Run("Successfully accepts request", func(t *testing.T) {
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
}

func createRemoteConfig() *remoteconfig.RemoteConfig {
	config := remoteconfig.New(remoteconfig.RemoteConfigOpts{
		HandleError: func(error) {},
	})
	return &config
}
