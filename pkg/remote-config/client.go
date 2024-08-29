package remoteconfig

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// fetch calls the supergood /v2/config endpoint and returns a marshalled config object
func (rc *RemoteConfig) fetch() (*RemoteConfigResponse, error) {
	url, err := url.JoinPath(rc.baseURL, "/v2/config")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(rc.clientID+":"+rc.clientSecret)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("supergood: invalid ClientID or ClientSecret")
	} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		message := string(body)
		return nil, fmt.Errorf("supergood: got HTTP %v posting to /v2/config with error: %s", resp.Status, message)
	}

	var remoteConfig RemoteConfigResponse
	err = json.NewDecoder(resp.Body).Decode(&remoteConfig)
	if err != nil {
		return nil, err
	}

	return &remoteConfig, nil
}
