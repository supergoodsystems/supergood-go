package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/supergoodsystems/supergood-go"
)

func main() {
	sg, err := supergood.New(&supergood.Options{
		ClientID:     os.Getenv("SUPERGOOD_CLIENT_ID"),
		ClientSecret: os.Getenv("SUPERGOOD_CLIENT_SECRET"),
	})
	if err != nil {
		panic(err)
	}
	defer sg.Close()
	http.DefaultClient = sg.DefaultClient

	resp, err := http.Get("https://supergood-testbed.herokuapp.com/")
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.Status)
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		panic(err)
	}
}
