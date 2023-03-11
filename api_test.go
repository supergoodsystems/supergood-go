package supergood

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestHelloEmpty calls greetings.Hello with an empty string,
// checking for an error.
func TestInterceptor(t *testing.T) {
	assert := assert.New(t)

	srv := httptest.NewServer(http.HandlerFunc((func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`Hello`))
	})))
	defer srv.Close()

	c := srv.Client()
	interceptor := SetupClient(c)

	_, err := c.Get(srv.URL)
	assert.Nil(err)

	requests := interceptor.GetCache()
	assert.Len(requests, 1)
	assert.EqualValues(requests[0].URL, srv.URL)
	assert.Greater(requests[0].duration, time.Duration(0))
}
