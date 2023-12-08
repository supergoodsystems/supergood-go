package remoteconfig

import (
	"regexp"
)

// createCache takes in the response body marshalled from the /config request and
// creates a remote config cache object used by supergood client to ignore/allow requests and
// to redact sensitive keys
func (rc *RemoteConfig) createCache(remoteConfigArray []RemoteConfigResponse) (map[string][]EndpointCacheVal, error) {
	remoteConfigMap := map[string][]EndpointCacheVal{}
	for _, config := range remoteConfigArray {
		cacheVal := []EndpointCacheVal{}
		for _, endpoint := range config.Endpoints {
			if endpoint.MatchingRegex.Regex == "" || endpoint.MatchingRegex.Location == "" {
				continue
			}
			regex, err := regexp.Compile(endpoint.MatchingRegex.Regex)
			if err != nil {
				return nil, err
			}
			endpointCacheVal := EndpointCacheVal{
				Regex:         *regex,
				Location:      endpoint.MatchingRegex.Location,
				Action:        endpoint.EndpointConfiguration.Action,
				SensitiveKeys: rc.mergeSensitiveKeysWithOptions(config.Domain, endpoint.EndpointConfiguration.SensitiveKeys),
			}
			cacheVal = append(cacheVal, endpointCacheVal)
		}
		remoteConfigMap[config.Domain] = cacheVal
	}
	return remoteConfigMap, nil
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
