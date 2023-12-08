package remoteconfig

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// fetch calls the supergood /config endpoint and returns a marshalled config object
func (rc *RemoteConfig) fetch() ([]RemoteConfigResponse, error) {
	url, err := url.JoinPath(rc.BaseURL, "/config")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(rc.ClientID+":"+rc.ClientSecret)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := rc.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("supergood: invalid ClientID or ClientSecret")
	} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		message := string(body)
		return nil, fmt.Errorf("supergood: got HTTP %v posting to /config with error: %s", resp.Status, message)
	}

	var remoteConfigArray []RemoteConfigResponse
	err = json.NewDecoder(resp.Body).Decode(&remoteConfigArray)
	if err != nil {
		return nil, err
	}

	return remoteConfigArray, nil
}
