package supergood

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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
	Regex    *regexp.Regexp
	Location string
	Action   string
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
	if endpoints == nil {
		return false
	}
	for _, endpoint := range *endpoints {
		testVal, err := marshalEndpointLocationValue(req, endpoint.Location)
		if err != nil {
			sg.options.OnError(err)
			continue
		}
		testByteArray := []byte(fmt.Sprintf("%v", testVal))
		match := endpoint.Regex.Match(testByteArray)
		if match {
			// Any value in remote config cache should not be ingested
			return true
		}
	}
	return false
}

func createRemoteConfigCache(remoteConfigArray []remoteConfig) (map[string]*[]endpointCacheVal, error) {
	remoteConfigMap := map[string]*[]endpointCacheVal{}
	for _, config := range remoteConfigArray {
		cacheVal := []endpointCacheVal{}
		for _, endpoint := range config.Endpoints {
			// NOTE: the remote config today is only used to block requests
			// from supergood ingest. We only need to track those endpoints that
			// should be ignored. All others that arent in remoteConfigMap can be allowed
			if endpoint.EndpointConfiguration.Action != "Ignore" {
				continue
			}
			if endpoint.MatchingRegex.Regex == "" || endpoint.MatchingRegex.Location == "" {
				continue
			}
			regex, err := regexp.Compile(endpoint.MatchingRegex.Regex)
			if err != nil {
				return nil, err
			}
			endpointCacheVal := endpointCacheVal{
				Regex:    regex,
				Location: endpoint.MatchingRegex.Location,
				Action:   endpoint.EndpointConfiguration.Action,
			}
			cacheVal = append(cacheVal, endpointCacheVal)
		}
		remoteConfigMap[config.Domain] = &cacheVal
	}
	return remoteConfigMap, nil
}

// mashalEndpointLocation value takes an endpoint location, which is used to uniquely classify
// a request and stringifies the request object at that location
func marshalEndpointLocationValue(req *http.Request, location string) (string, error) {
	switch location {
	case "subdomain":
		return req.URL.Host, nil
	case "url":
		return req.URL.String(), nil
	case "path":
		return req.URL.Path, nil
	case "domain":
		return req.URL.Host, nil
	case "request_body":
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return "", err
		}
		req.Body = io.NopCloser(bytes.NewBuffer(body))
		return string(body), nil
	case "request_headers":
		return fmt.Sprint(req.Header), nil
	default:
		return "", errors.New("invalid location parameter for RegExp matching")
	}
}
