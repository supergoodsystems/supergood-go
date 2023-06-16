package supergood_test

import (
	"context"
	"net/http"
	"os"

	"github.com/supergoodsystems/supergood-go"
	"golang.org/x/oauth2"
)

func Example() {
	sg, err := supergood.New(&supergood.Options{
		ClientID:     os.Getenv("SUPERGOOD_CLIENT_ID"),
		ClientSecret: os.Getenv("SUPERGOOD_CLIENT_SECRET"),
	})
	if err != nil {
		panic(err)
	}
	defer sg.Close()
	// enable supergood globally
	http.DefaultClient = sg.DefaultClient

	http.Get("https://api.example.com/")
}

func ExampleService() {
	sg, err := supergood.New(&supergood.Options{
		ClientID:     os.Getenv("SUPERGOOD_CLIENT_ID"),
		ClientSecret: os.Getenv("SUPERGOOD_CLIENT_SECRET"),
	})
	if err != nil {
		panic(err)
	}
	defer sg.Close()

	// use the supergood client to make requests
	sg.DefaultClient.Get("https://api.example.com")
}

func ExampleService_Wrap() {
	sg, err := supergood.New(&supergood.Options{
		ClientID:     os.Getenv("SUPERGOOD_CLIENT_ID"),
		ClientSecret: os.Getenv("SUPERGOOD_CLIENT_SECRET"),
	})
	if err != nil {
		panic(err)
	}
	defer sg.Close()

	// The oauth2 library returns an http client that makes authenticated requests.
	// If you have not set http.DefaultClient = sg.DefaultClient, you can ensure
	// these requests are logged by wrapping the oauth2 client.
	config := &oauth2.Config{ /* ... */ }
	client := config.Client(context.Background(), &oauth2.Token{ /* ... */ })
	client = sg.Wrap(client)

	resp, err := client.Get("https://api.example.com/")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}
