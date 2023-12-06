package supergood

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/supergoodsystems/supergood-go/domainutils"
)

type remoteConfig struct {
	Id        string     `json:"id"`
	Domain    string     `json:"domain"`
	Name      string     `json:"name"`
	Endpoints []endpoint `json:"endpoints"`
}

type endpoint struct {
	Id                    string                `json:"id"`
	Name                  string                `json:"name"`
	MatchingRegex         matchingRegex         `json:"matchingRegex"`
	EndpointConfiguration endpointConfiguration `json:"endpointConfiguration"`
}

type matchingRegex struct {
	Location string `json:"location"`
	Regex    string `json:"regex"`
}

type endpointConfiguration struct {
	Id            string          `json:"id"`
	Acknowledged  bool            `json:"acknowledged"`
	Action        string          `json:"action"`
	UpdatedAt     time.Time       `json:"updatedAt"`
	SensitiveKeys []sensitiveKeys `json:"sensitiveKeys"`
}

type sensitiveKeys struct {
	Id        string    `json:"id"`
	KeyPath   string    `json:"keyPath"`
	Action    string    `json:"action"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type endpointCacheVal struct {
	Regex         *regexp.Regexp
	Location      string
	Action        string
	SensitiveKeys []sensitiveKeys
}

func (sg *Service) initRemoteConfig() error {
	return sg.fetchRemoteConfig()
}

func (sg *Service) refreshRemoteConfig() {
	for {
		select {
		case <-sg.remoteConfigClose:
			return
		case <-time.After(sg.options.RemoteConfigFetchInterval):
			if err := sg.fetchRemoteConfig(); err != nil {
				sg.handleError(err)
			}
		}
	}
}

func (sg *Service) fetchRemoteConfig() error {
	url, err := url.JoinPath(sg.options.BaseURL, "/config")
	if err != nil {
		return err
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(sg.options.ClientID+":"+sg.options.ClientSecret)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := sg.options.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("supergood: invalid ClientID or ClientSecret")
	} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		message := string(body)
		return fmt.Errorf("supergood: got HTTP %v posting to /config with error: %s", resp.Status, message)
	}

	var remoteConfigArray []remoteConfig
	err = json.NewDecoder(resp.Body).Decode(&remoteConfigArray)
	if err != nil {
		return err
	}

	remoteConfigCache, err := createRemoteConfigCache(remoteConfigArray)
	if err != nil {
		return err
	}

	sg.remoteConfigCache = remoteConfigCache
	return nil
}

func (sg *Service) shouldIgnoreRequestRemoteConfig(req *http.Request) bool {
	domain := domainutils.Domain(req.Host)
	if domain == "" {
		domain = domainutils.Subdomain(req.Host)
	}
	if domain == "" {
		return false
	}

	endpoints := sg.remoteConfigCache[domain]
	if len(endpoints) == 0 {
		return false
	}
	for _, endpoint := range endpoints {
		if endpoint.Action != "Ignore" {
			continue
		}
		testVal, err := marshalEndpointLocation(req, endpoint.Location)
		if err != nil {
			sg.options.OnError(err)
			continue
		}
		testByteArray := []byte(fmt.Sprintf("%v", testVal))
		match := endpoint.Regex.Match(testByteArray)
		if match {
			return true
		}
	}
	return false
}

func createRemoteConfigCache(remoteConfigArray []remoteConfig) (map[string][]endpointCacheVal, error) {
	remoteConfigMap := map[string][]endpointCacheVal{}
	for _, config := range remoteConfigArray {
		cacheVal := []endpointCacheVal{}
		for _, endpoint := range config.Endpoints {
			if endpoint.MatchingRegex.Regex == "" || endpoint.MatchingRegex.Location == "" {
				continue
			}
			regex, err := regexp.Compile(endpoint.MatchingRegex.Regex)
			if err != nil {
				return nil, err
			}
			endpointCacheVal := endpointCacheVal{
				Regex:         regex,
				Location:      endpoint.MatchingRegex.Location,
				Action:        endpoint.EndpointConfiguration.Action,
				SensitiveKeys: endpoint.EndpointConfiguration.SensitiveKeys,
			}
			cacheVal = append(cacheVal, endpointCacheVal)
		}
		remoteConfigMap[config.Domain] = cacheVal
	}
	return remoteConfigMap, nil
}

// mashalEndpointLocation takes an endpoint location, which is used to uniquely classify
// a request and stringifies the request object at that location
func marshalEndpointLocation(req *http.Request, location string) (string, error) {
	if location == "url" {
		return req.URL.String(), nil
	}
	if location == "domain" {
		return domainutils.Domain(req.URL.String()), nil
	}
	if location == "subdomain" {
		return domainutils.Subdomain(req.URL.String()), nil
	}
	if location == "path" {
		return req.URL.Path, nil
	}
	if strings.Contains(location, "request_headers") {
		return getHeaderValueAtLocation(req.Header, location)
	}
	if strings.Contains(location, "request_body") {
		return getRequestBodyValueAtLocation(req, location)
	}

	return "", fmt.Errorf("unexpected location parameter for RegExp matching: %s", location)
}

// getHeaderValueAtLocation retrieves the header value string given a header key "location"
func getHeaderValueAtLocation(headers http.Header, location string) (string, error) {
	path := strings.Split(location, ".")
	// location here is of form: request_header
	if len(path) == 1 {
		headerBytes, err := json.Marshal(headers)
		if err != nil {
			return "", err
		}
		return string(headerBytes), nil
	}

	// location here is of form: request_header.Client-Secret
	if len(path) != 2 {
		return "", fmt.Errorf("invalid header parameter for RegExp matching: %s", location)
	}
	return headers.Get(path[1]), nil

}

// getRequestBodyValueAtLocation retrieves the nested field value of a struct based on the given "location"
func getRequestBodyValueAtLocation(req *http.Request, location string) (string, error) {
	path := strings.Split(location, ".")

	// read in stream and write back to request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	// no nested field provided in location parameter (e.g. "request_body" instead of "request_body.field")
	if len(path) == 1 || !json.Valid(body) {
		return string(body), nil
	}

	var nestedBody map[string]interface{}
	err = json.Unmarshal(body, &nestedBody)
	if err != nil {
		return "", err
	}

	path = path[1:]
	for _, key := range path {
		value, ok := nestedBody[key]
		if !ok {
			return "", fmt.Errorf("field not found: %s", location)
		}

		if nested, ok := value.(map[string]interface{}); ok {
			nestedBody = nested
		} else {
			// If not a map, this is the final value
			return fmt.Sprintf("%v", value), nil
		}
	}
	return "", fmt.Errorf("field not found: %s", location)
}
