package supergood

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
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

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var remoteConfigArray []remoteConfig
	json.NewDecoder(resp.Body).Decode(&remoteConfigArray)
	remoteConfigMap := map[string][]endpointCacheVal{}
	for _, config := range remoteConfigArray {
		cacheVal := []endpointCacheVal{}
		for _, endpoint := range config.Endpoints {
			// NOTE: the remote config today is only used to block requests
			// from supergood ingest. We only need to track those endpoints that
			// should be ignored. All others that arent in remoteConfigMap can be allowed
			if endpoint.EndpointConfiguration.Action != "Ignore" {
				continue
			}
			regex, err := regexp.Compile(endpoint.MatchingRegex.Regex)
			if err != nil {
				return err
			}
			endpointCacheVal := endpointCacheVal{
				Regex:    regex,
				Location: endpoint.MatchingRegex.Location,
				Action:   endpoint.EndpointConfiguration.Action,
			}
			cacheVal = append(cacheVal, endpointCacheVal)
		}

		remoteConfigMap[config.Domain] = cacheVal
	}

	sg.remoteConfigCache = remoteConfigMap
	return nil
}

func (sg *Service) initRemoteConfig() error {
	return sg.fetchRemoteConfig()
}

func (sg *Service) shouldIgnoreRequestRemoteConfig(req *http.Request) bool {
	shouldIgnore := false
	baseUrlHostName := strings.TrimPrefix(req.URL.Hostname(), "www.")
	endpoints := sg.remoteConfigCache[baseUrlHostName]

	for _, endpoint := range endpoints {
		testVal := getNestedFieldValue(req, endpoint.Location)
		if testVal == nil {
			continue
		}

		testByteArray := []byte(fmt.Sprintf("%v", testVal))
		match := endpoint.Regex.Match(testByteArray)
		if match {
			// Any value in remote config cache should not be ingested
			return true
		}
	}
	return shouldIgnore
}

// getNestedFieldValue retrieves the nested field value of a struct based on the given location string.
func getNestedFieldValue(obj interface{}, location string) interface{} {
	// Split the location string into nested field names
	fieldNames := strings.Split(location, ".")

	// Use reflection to navigate through the nested fields
	value := reflect.ValueOf(obj)
	for _, fieldName := range fieldNames {
		if value.Kind() == reflect.Ptr {
			value = value.Elem()
		}

		// Get the field by name
		field := value.FieldByName(fieldName)
		if !field.IsValid() {
			return nil
		}

		// Update the value to the nested field's value
		value = field
	}

	return value.Interface()
}
