package supergood

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Basic test for intercepting HTTP requests and logging them to supergood.
func TestInterceptor(t *testing.T) {
	assert := assert.New(t)

	srv := httptest.NewServer(http.HandlerFunc((func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`Hello`))
	})))
	defer srv.Close()

	c := srv.Client()
	interceptor := InitWithClient(c)
	testUrl := srv.URL + "/test?args=1"
	_, err := c.Get(testUrl)
	assert.Nil(err)

	responses := []RequestResponse{}
	for _, value := range interceptor.Close() {
		responses = append(responses, value)
	}

	fmt.Printf("%+v\n", responses[0].request)

	assert.Len(responses, 1)
	assert.EqualValues(responses[0].request.path, "/test")
	assert.EqualValues(responses[0].request.search, "args=1")
	assert.EqualValues(responses[0].request.url, testUrl)
	assert.Greater(responses[0].response.duration, time.Duration(0))
}
