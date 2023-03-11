package supergood

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHelloEmpty calls greetings.Hello with an empty string,
// checking for an error.
func TestInterceptor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc((func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%+v\n", r)
		t.Log("Hello")
		w.Write([]byte(`{"isItSunday": true}`))
	})))
	defer srv.Close()

	c := srv.Client()
	SetupClient(c)

	_, err := c.Get(srv.URL)
	if err != nil {
		t.Logf("%+v", err)
		t.Fail()
	}
}
