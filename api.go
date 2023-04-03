package supergood

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

type SupergoodApi struct {
	baseUrl             string
	authorizationString string
	eventSinkEndpoint   string
	errorSinkEndpoint   string
}

func (api *SupergoodApi) SetAuthorizationString(clientId string, clientSecret string) string {
	api.authorizationString = b64.StdEncoding.EncodeToString([]byte(clientId + ":" + clientSecret))
	return api.authorizationString
}

func (api *SupergoodApi) PostEvents(events []RequestResponse) {
	jsonBody, jsonErr := json.Marshal(events)

	if jsonErr != nil {
		fmt.Println("JSON Error")
		return
	}

	bodyReader := bytes.NewReader(jsonBody)
	req, err := http.NewRequest(http.MethodPost, api.baseUrl+api.eventSinkEndpoint, bodyReader)

	if err != nil {
		fmt.Println("Request Error")
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+api.authorizationString)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Response Error")
		return
	}
	defer res.Body.Close()
}

func (api *SupergoodApi) PostErrors(err *SupergoodError) {

}

func (api *SupergoodApi) FetchConfig() *SupergoodConfig {
	req, err := http.NewRequest(http.MethodGet, api.baseUrl+"/api/config", nil)

	if err != nil {
		fmt.Println("Request Error")
		return nil
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+api.authorizationString)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Response Error")
		fmt.Println(err)
		return nil
	}

	defer res.Body.Close()

	config := new(SupergoodConfig)
	err = json.NewDecoder(res.Body).Decode(&config)

	if err != nil {
		fmt.Println("Decode Error")
		return nil
	}

	return config
}
