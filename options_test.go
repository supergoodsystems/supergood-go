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

	require.False(t, o.RedactRequestBody)
	require.Equal(t, len(o.IncludeSpecifiedRequestBodyKeys), 0)
	require.False(t, o.RedactResponseBody)
	require.Equal(t, len(o.IncludeSpecifiedResponseBodyKeys), 0)
	require.Equal(t, len(o.AllowedDomains), 0)
	require.Equal(t, len(o.IncludeSpecifiedRequestHeaderKeys), 0)
	require.True(t, o.SelectRequests(nil))
	require.NotNil(t, o.OnError)
	require.Equal(t, o.FlushInterval, 1*time.Second)
	require.Equal(t, o.HTTPClient, http.DefaultClient)
}

func TestOptions_overrides(t *testing.T) {
	var onErr error
	client := &http.Client{}

	o, err := (&Options{
		ClientID:                          "test_client_id2",
		ClientSecret:                      "test_client_secret2",
		BaseURL:                           "https://api.superbad.ai",
		RedactRequestBody:                 true,
		RedactResponseBody:                true,
		IncludeSpecifiedResponseBodyKeys:  map[string]bool{"foo": true},
		IncludeSpecifiedRequestBodyKeys:   map[string]bool{"bar": true},
		IncludeSpecifiedRequestHeaderKeys: map[string]bool{"authz": true},
		AllowedDomains:                    []string{"example.com"},
		SelectRequests:                    func(r *http.Request) bool { return false },
		OnError:                           func(e error) { onErr = e },
		FlushInterval:                     5 * time.Second,
		HTTPClient:                        client,
	}).parse()
	require.NoError(t, err)

	require.Equal(t, "test_client_id2", o.ClientID)
	require.Equal(t, "test_client_secret2", o.ClientSecret)
	require.Equal(t, "https://api.superbad.ai", o.BaseURL)
	require.True(t, o.RedactRequestBody)
	require.True(t, o.RedactResponseBody)
	require.False(t, o.IncludeSpecifiedRequestHeaderKeys["authorization"])
	require.True(t, o.IncludeSpecifiedRequestHeaderKeys["authz"])
	require.True(t, o.IncludeSpecifiedResponseBodyKeys["foo"])
	require.True(t, o.IncludeSpecifiedRequestBodyKeys["bar"])
	require.False(t, o.IncludeSpecifiedRequestBodyKeys["baz"])
	require.Equal(t, []string{"example.com"}, o.AllowedDomains)
	o.OnError(fmt.Errorf("test error"))
	require.Equal(t, "test error", onErr.Error())
	require.Equal(t, o.FlushInterval, 5*time.Second)
	require.Equal(t, o.HTTPClient, client)
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
