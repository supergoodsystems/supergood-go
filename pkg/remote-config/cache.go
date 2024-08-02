package remoteconfig

import (
	"fmt"
	"regexp"

	"github.com/supergoodsystems/supergood-go/internal/shared"
)

// Get retrieves an object from the remote config cache
func (rc *RemoteConfig) Get(domain string) map[string]EndpointCacheVal {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()
	val := rc.cache[domain]
	return val
}

// Set sets an endpoint cache val into the remote config cache
func (rc *RemoteConfig) Set(domain string, val map[string]EndpointCacheVal) error {
	if rc.cache == nil {
		return fmt.Errorf("failed to set cache val in remote config cache. remote config cachee not initialized")
	}
	rc.mutex.Lock()
	defer rc.mutex.Unlock()
	rc.cache[domain] = val
	return nil
}

func (rc *RemoteConfig) IsInitialized() bool {
	return rc.initialized
}

func (rc *RemoteConfig) IsRedactAllEnabled() bool {
	return rc.redactAll
}

// Create takes in the response body marshalled from the /config request and
// creates a remote config cache object used by supergood client to ignore/allow requests and
// to redact sensitive keys
func (rc *RemoteConfig) Create(remoteConfigArray []RemoteConfigResponse) error {
	for _, config := range remoteConfigArray {
		cacheVal := map[string]EndpointCacheVal{}
		for _, endpoint := range config.Endpoints {
			if endpoint.MatchingRegex.Regex == "" || endpoint.MatchingRegex.Location == "" {
				continue
			}
			regex, err := regexp.Compile(endpoint.MatchingRegex.Regex)
			if err != nil {
				return err
			}
			endpointCacheVal := EndpointCacheVal{
				Id:            endpoint.Id,
				Method:        endpoint.Method,
				Regex:         *regex,
				Location:      endpoint.MatchingRegex.Location,
				Action:        endpoint.EndpointConfiguration.Action,
				ProxyRequest:  config.ProxyRequest,
				SensitiveKeys: rc.mergeSensitiveKeysOptions(config.Domain, endpoint.EndpointConfiguration.SensitiveKeys),
			}
			cacheVal[endpoint.Id] = endpointCacheVal
		}
		err := rc.Set(config.Domain, cacheVal)
		if err != nil {
			return err
		}
	}
	return nil
}

func (rc *RemoteConfig) Close() {
	rc.close <- struct{}{}
	close(rc.close)
}

func (rc *RemoteConfig) mergeSensitiveKeysOptions(domain string, sensitiveKeys []SensitiveKeys) []SensitiveKeys {
	mergedKeys := sensitiveKeys
	for _, keyStr := range rc.redactRequestHeaderKeys[domain] {
		key := SensitiveKeys{
			KeyPath: shared.RequestHeadersStr + "." + keyStr,
		}
		mergedKeys = append(mergedKeys, key)
	}

	for _, keyStr := range rc.redactRequestBodyKeys[domain] {
		key := SensitiveKeys{
			KeyPath: shared.RequestBodyStr + "." + keyStr,
		}
		mergedKeys = append(mergedKeys, key)
	}

	for _, keyStr := range rc.redactResponseBodyKeys[domain] {
		key := SensitiveKeys{
			KeyPath: shared.ResponseBodyStr + "." + keyStr,
		}
		mergedKeys = append(mergedKeys, key)
	}
	return mergedKeys
}
