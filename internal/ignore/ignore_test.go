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
		ignore := ShouldIgnoreRequest(req, config, func(error) {})
		require.Equal(t, true, ignore)
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
		ignore := ShouldIgnoreRequest(req, config, func(error) {})
		require.Equal(t, false, ignore)
	})
}

func createRemoteConfig() *remoteconfig.RemoteConfig {
	config := remoteconfig.New(remoteconfig.RemoteConfigOpts{
		HandleError: func(error) {},
	})
	return &config
}

// t.Run("SelectRequests", func(t *testing.T) {
// 	echo(t, &Options{
// 		SelectRequests: func(r *http.Request) bool {
// 			if r.Method == "POST" && r.URL.Path == "/echo" {
// 				return false
// 			}
// 			return true
// 		},
// 	})
// 	require.Len(t, events, 0)
// })
