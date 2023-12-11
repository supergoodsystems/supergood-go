package remoteconfig

import (
	"fmt"
	"regexp"
)

// Get retrieves an object from the remote config cache
func (rc *RemoteConfig) Get(domain string) ([]EndpointCacheVal, error) {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()
	val, ok := rc.Cache[domain]
	if !ok {
		return nil, fmt.Errorf("failed to find %s domain in cache", domain)
	}
	return val, nil
}

// Set sets an endpoint cache val into the remote config cache
func (rc *RemoteConfig) Set(domain string, val []EndpointCacheVal) error {
	if rc.Cache == nil {
		return fmt.Errorf("failed to set cache val in remote config cache. remote config cachee not initialized")
	}
	rc.mutex.Lock()
	defer rc.mutex.Unlock()
	rc.Cache[domain] = val
	return nil
}

// Create takes in the response body marshalled from the /config request and
// creates a remote config cache object used by supergood client to ignore/allow requests and
// to redact sensitive keys
func (rc *RemoteConfig) Create(remoteConfigArray []RemoteConfigResponse) error {
	remoteConfigMap := map[string][]EndpointCacheVal{}
	for _, config := range remoteConfigArray {
		cacheVal := []EndpointCacheVal{}
		for _, endpoint := range config.Endpoints {
			if endpoint.MatchingRegex.Regex == "" || endpoint.MatchingRegex.Location == "" {
				continue
			}
			regex, err := regexp.Compile(endpoint.MatchingRegex.Regex)
			if err != nil {
				return err
			}
			endpointCacheVal := EndpointCacheVal{
				Regex:         *regex,
				Location:      endpoint.MatchingRegex.Location,
				Action:        endpoint.EndpointConfiguration.Action,
				SensitiveKeys: rc.mergeSensitiveKeysWithOptions(config.Domain, endpoint.EndpointConfiguration.SensitiveKeys),
			}
			cacheVal = append(cacheVal, endpointCacheVal)
		}
		rc.Set(config.Domain, cacheVal)
		remoteConfigMap[config.Domain] = cacheVal
	}
	return nil
}

func (rc *RemoteConfig) mergeSensitiveKeysWithOptions(domain string, sensitiveKeys []SensitiveKeys) []SensitiveKeys {
	mergedKeys := sensitiveKeys
	for _, keyStr := range rc.RedactRequestHeaderKeys[domain] {
		key := SensitiveKeys{
			KeyPath: RequestHeadersStr + "." + keyStr,
		}
		mergedKeys = append(mergedKeys, key)
	}

	for _, keyStr := range rc.RedactRequestBodyKeys[domain] {
		key := SensitiveKeys{
			KeyPath: RequestBodyStr + "." + keyStr,
		}
		mergedKeys = append(mergedKeys, key)
	}

	for _, keyStr := range rc.RedactResponseBodyKeys[domain] {
		key := SensitiveKeys{
			KeyPath: ResponseBodyStr + "." + keyStr,
		}
		mergedKeys = append(mergedKeys, key)
	}
	return mergedKeys
}
