package supergood

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOptions_defaults(t *testing.T) {
	t.Setenv("SUPERGOOD_CLIENT_ID", "test_client_id")
	t.Setenv("SUPERGOOD_CLIENT_SECRET", "test_client_secret")

	var o *Options
	o, err := o.parse()
	require.NoError(t, err)

	require.Equal(t, "test_client_id", o.ClientID)
	require.Equal(t, "test_client_secret", o.ClientSecret)
	require.Equal(t, "https://api.supergood.ai", o.BaseURL)

	require.Equal(t, len(o.RedactRequestBodyKeys), 0)
	require.Equal(t, len(o.RedactResponseBodyKeys), 0)
	require.Equal(t, len(o.AllowedDomains), 0)
	require.Equal(t, len(o.RedactRequestHeaderKeys), 0)
	require.Nil(t, o.SelectRequests)
	require.NotNil(t, o.OnError)
	require.Equal(t, o.FlushInterval, 1*time.Second)
	require.Equal(t, o.HTTPClient, http.DefaultClient)
	require.False(t, o.DisableDefaultWrappedClient)
}

func TestOptions_overrides(t *testing.T) {
	var onErr error
	client := &http.Client{}

	o, err := (&Options{
		ClientID:                    "test_client_id2",
		ClientSecret:                "test_client_secret2",
		BaseURL:                     "https://api.superbad.ai",
		RedactResponseBodyKeys:      map[string][]string{"example.com": {"responsebody.path.to.key"}},
		RedactRequestBodyKeys:       map[string][]string{"example.com": {"requestbody.path.to.key"}},
		RedactRequestHeaderKeys:     map[string][]string{"example.com": {"header-key"}},
		AllowedDomains:              []string{"example.com"},
		SelectRequests:              func(r *http.Request) bool { return false },
		OnError:                     func(e error) { onErr = e },
		FlushInterval:               5 * time.Second,
		HTTPClient:                  client,
		DisableDefaultWrappedClient: true,
	}).parse()
	require.NoError(t, err)

	require.Equal(t, "test_client_id2", o.ClientID)
	require.Equal(t, "test_client_secret2", o.ClientSecret)
	require.Equal(t, "https://api.superbad.ai", o.BaseURL)
	require.Empty(t, o.RedactRequestHeaderKeys["notconfigured.com"])
	require.Equal(t, "header-key", o.RedactRequestHeaderKeys["example.com"][0])
	require.Equal(t, "requestbody.path.to.key", o.RedactRequestBodyKeys["example.com"][0])
	require.Equal(t, "responsebody.path.to.key", o.RedactResponseBodyKeys["example.com"][0])
	require.Equal(t, []string{"example.com"}, o.AllowedDomains)
	o.OnError(fmt.Errorf("test error"))
	require.Equal(t, "test error", onErr.Error())
	require.Equal(t, o.FlushInterval, 5*time.Second)
	require.Equal(t, o.HTTPClient, client)
	require.True(t, o.DisableDefaultWrappedClient)
}

func TestOptions_errors(t *testing.T) {
	t.Setenv("SUPERGOOD_CLIENT_ID", "")
	t.Setenv("SUPERGOOD_CLIENT_SECRET", "")
	for _, o := range []*Options{
		{ClientID: "", ClientSecret: "x"},
		{ClientID: "x", ClientSecret: ""},
		{ClientID: "x", ClientSecret: "x", BaseURL: "oops"},
		{ClientID: "x", ClientSecret: "x", FlushInterval: 1},
	} {
		_, err := New(o)
		require.Error(t, err)
	}

	_, err := New(&Options{AllowedDomains: []string{"superbad.ai"}})
	require.Error(t, err)
}
